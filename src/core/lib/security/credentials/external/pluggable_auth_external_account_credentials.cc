//
// Copyright 2023 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include <grpc/support/port_platform.h>

#include "src/core/lib/security/credentials/external/pluggable_auth_external_account_credentials.h"

#include <cxxabi.h>

#include <chrono>
#include <fstream>
#include <future>
#include <initializer_list>
#include <map>
#include <memory>
#include <thread>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"

#include <grpc/support/json.h>
#include <grpc/support/time.h>

#include "src/core/lib/gpr/subprocess.h"
#include "src/core/lib/iomgr/load_file.h"
#include "src/core/lib/json/json.h"
#include "src/core/lib/json/json_reader.h"
#include "src/core/lib/security/credentials/external/external_account_credentials.h"

#define DEFAULT_EXECUTABLE_TIMEOUT_MS 30000  // 30 seconds
#define MIN_EXECUTABLE_TIMEOUT_MS 5000       // 5 seconds
#define MAX_EXECUTABLE_TIMEOUT_MS 120000     // 120 seconds
#define SAML_SUBJECT_TOKEN_TYPE "urn:ietf:params:oauth:token-type:saml2"

inline bool isKeyPresent(absl::StatusOr<grpc_core::Json> json,
                         std::string key) {
  return json->object().find(key.c_str()) != json->object().end();
}

bool isExpired(int64_t expiration_time) {
  // int32_t cmp =
  //     gpr_time_cmp(gpr_time_from_seconds(expiration_time,
  //     GPR_CLOCK_REALTIME),
  //                  gpr_now(GPR_CLOCK_REALTIME));
  // std::cout << "cmp: " << cmp << "\n";
  // return cmp <= 0;
  std::cout << "In isExpired\n";
  return false;
}

std::string read_file_contents(std::string file_path) {
  std::string content = "", line;
  std::ifstream file_ifstream(file_path);
  if (file_ifstream.is_open()) {
    while (getline(file_ifstream, line)) {
      absl::StrAppend(&content, line);
    }
  }
  return content;
}

std::string get_impersonated_email(
    std::string service_account_impersonation_url) {
  std::vector<absl::string_view> url_elements =
      absl::StrSplit(service_account_impersonation_url, "/");
  absl::string_view impersonated_email = url_elements[url_elements.size() - 1];
  absl::ConsumeSuffix(&impersonated_email, ":generateAccessToken");
  return {impersonated_email.data(), impersonated_email.size()};
}

bool run_executable(Subprocess* subprocess, std::string command,
                    std::vector<std::string> envp, std::string* output,
                    std::string* error) {
  subprocess->Start(command, envp);
  return subprocess->Communicate("", output, error);
}

namespace grpc_core {

RefCountedPtr<PluggableAuthExternalAccountCredentials>
PluggableAuthExternalAccountCredentials::Create(Options options,
                                                std::vector<std::string> scopes,
                                                grpc_error_handle* error) {
  auto creds = MakeRefCounted<PluggableAuthExternalAccountCredentials>(
      std::move(options), std::move(scopes), error);
  if (error->ok())
    return creds;
  else
    return nullptr;
}

PluggableAuthExternalAccountCredentials::
    PluggableAuthExternalAccountCredentials(Options options,
                                            std::vector<std::string> scopes,
                                            grpc_error_handle* error)
    : ExternalAccountCredentials(options, std::move(scopes)) {
  auto it = options.credential_source.object().find("executable");
  if (it->second.type() != Json::Type::kObject) {
    *error = GRPC_ERROR_CREATE("executable field must be an object");
    return;
  }
  auto executable_json = it->second;
  auto executable_it = executable_json.object().find("command");
  if (executable_it == executable_json.object().end()) {
    *error = GRPC_ERROR_CREATE("command field not present.");
    return;
  }
  if (executable_it->second.type() != Json::Type::kString) {
    *error = GRPC_ERROR_CREATE("command field must be a string.");
    return;
  }
  command_ = executable_it->second.string();
  executable_timeout_ms_ = DEFAULT_EXECUTABLE_TIMEOUT_MS;
  executable_it = executable_json.object().find("timeout_millis");
  if (executable_it != executable_json.object().end()) {
    if (!absl::SimpleAtoi(executable_it->second.string(),
                          &executable_timeout_ms_)) {
      *error = GRPC_ERROR_CREATE("timeout_millis field must be a number.");
      return;
    }
    if (executable_timeout_ms_ > MAX_EXECUTABLE_TIMEOUT_MS ||
        executable_timeout_ms_ < MIN_EXECUTABLE_TIMEOUT_MS) {
      *error = GRPC_ERROR_CREATE(absl::StrFormat(
          "timeout_millis should be between %d and %d milliseconds.",
          MIN_EXECUTABLE_TIMEOUT_MS, MAX_EXECUTABLE_TIMEOUT_MS));
      return;
    }
  }
  executable_it = executable_json.object().find("output_file");
  if (executable_it != executable_json.object().end()) {
    if (executable_it->second.type() != Json::Type::kString) {
      *error = GRPC_ERROR_CREATE("output_file field must be a string.");
      return;
    }
    output_file_path_ = executable_it->second.string();
  }

  audience_ = options.audience;
  subject_token_type_ = options.subject_token_type;
  impersonation_url_ = options.service_account_impersonation_url;
}

void PluggableAuthExternalAccountCredentials::CreateExecutableResponse(
    std::string executable_output_string) {
  ExecutableResponse* executable_response =
      static_cast<ExecutableResponse*>(gpr_malloc(sizeof(ExecutableResponse)));
  auto executable_output = JsonParse(executable_output_string);
  if (!executable_output.ok() &&
      executable_output->type() != Json::Type::kObject) {
    FinishRetrieveSubjectToken(
        "", GRPC_ERROR_CREATE("Executable output could not be parsed."));
  }
  auto executable_output_it = executable_output->object().find("version");
  if (!isKeyPresent(executable_output, "version")) {
    FinishRetrieveSubjectToken(
        "", GRPC_ERROR_CREATE("The executable response must contain the "
                              "`version` field."));
  }
  absl::SimpleAtoi(executable_output_it->second.string(),
                   &executable_response->version);
  executable_output_it = executable_output->object().find("success");
  if (!isKeyPresent(executable_output, "success")) {
    FinishRetrieveSubjectToken(
        "", GRPC_ERROR_CREATE("The executable response must contain the "
                              "`success` field."));
  }
  executable_response->success = executable_output_it->second.boolean();
  if (executable_response->success) {
    executable_output_it = executable_output->object().find("token_type");
    if (!isKeyPresent(executable_output, "token_type")) {
      FinishRetrieveSubjectToken(
          "", GRPC_ERROR_CREATE("The executable response must contain the "
                                "`token_type` field."));
    }
    executable_response->token_type = executable_output_it->second.string();
    executable_response->expiration_time = 0;
    executable_output_it = executable_output->object().find("expiration_time");
    if (isKeyPresent(executable_output, "expiration_time")) {
      absl::SimpleAtoi(executable_output_it->second.string(),
                       &executable_response->expiration_time);
    }
    if (strcmp(executable_response->token_type.c_str(),
               SAML_SUBJECT_TOKEN_TYPE) == 0)
      executable_output_it = executable_output->object().find("saml_response");
    else
      executable_output_it = executable_output->object().find("id_token");
    if (executable_output_it == executable_output->object().end()) {
      FinishRetrieveSubjectToken(
          "", GRPC_ERROR_CREATE(
                  "The executable response must contain a valid token."));
    }
    executable_response->subject_token = executable_output_it->second.string();
  } else {
    executable_output_it = executable_output->object().find("code");
    if (executable_output_it == executable_output->object().end()) {
      FinishRetrieveSubjectToken(
          "", GRPC_ERROR_CREATE("The executable response must contain the "
                                "`code` field when unsuccessful."));
    }
    executable_response->error_code = executable_output_it->second.string();
    executable_output_it = executable_output->object().find("message");
    if (executable_output_it == executable_output->object().end()) {
      FinishRetrieveSubjectToken(
          "", GRPC_ERROR_CREATE("The executable response must contain the "
                                "`message` field when unsuccessful."));
    }
    executable_response->error_message = executable_output_it->second.string();
  }
  // if (output_file_path_ != "") {
  //   executable_output_it =
  //   executable_output->object().find("expiration_time"); if
  //   (executable_output_it == executable_output->object().end() ||
  //       executable_output_it->second.string() == "") {
  //     FinishRetrieveSubjectToken(
  //         "", GRPC_ERROR_CREATE(
  //                 "The executable response must contain the "
  //                 "`expiration_time` field for successful responses when an "
  //                 "output_file has been specified in the configuration."));
  //     executable_response_ = nullptr;
  //     return;
  //   }
  // }
  executable_response_ = executable_response;
}

void PluggableAuthExternalAccountCredentials::RetrieveSubjectToken(
    HTTPRequestContext* /*ctx*/, const Options& /*options*/,
    std::function<void(std::string, grpc_error_handle)> cb) {
  cb_ = cb;
  struct SliceWrapper {
    ~SliceWrapper() { CSliceUnref(slice); }
    grpc_slice slice = grpc_empty_slice();
  };
  SliceWrapper content_slice;
  // To retrieve the subject token, we read the file every time we make a
  // request because it may have changed since the last request.
  grpc_error_handle error =
      grpc_load_file(output_file_path_.c_str(), 0, &content_slice.slice);
  if (error.ok()) {
    absl::string_view output_file_content =
        StringViewFromSlice(content_slice.slice);
    CreateExecutableResponse(
        {output_file_content.data(), output_file_content.size()});
    std::cout << "Here";
    std::cout << "Exec resp: " << executable_response_ << "\n";
    if (executable_response_ != nullptr) {
      // if (executable_response_ != nullptr && executable_response_->success) {
      // !isExpired(executable_response_->expiration_time)) {
      OnRetrieveSubjectToken();
      return;
    } else
      executable_response_ = nullptr;
  }

  std::vector<std::string> envp = {
      absl::StrFormat("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE=%s", audience_),
      absl::StrFormat("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE=%s",
                      subject_token_type_),
      absl::StrFormat("GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE=%d", 0),
      absl::StrFormat("GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL=%s",
                      get_impersonated_email(impersonation_url_)),
      absl::StrFormat("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE=%s",
                      output_file_path_)};
  Subprocess* subprocess = new Subprocess();
  std::packaged_task<bool(Subprocess*, std::string, std::vector<std::string>,
                          std::string*, std::string*)>
      run_executable_task(run_executable);
  std::future<bool> executable_output_future = run_executable_task.get_future();
  std::string output_string, error_string;
  std::thread thr(std::move(run_executable_task), subprocess, command_, envp,
                  &output_string, &error_string);
  if (executable_output_future.wait_for(std::chrono::seconds(
          executable_timeout_ms_ / 1000)) != std::future_status::timeout) {
    thr.join();
    if (!executable_output_future.get()) {
      FinishRetrieveSubjectToken(
          "",
          GRPC_ERROR_CREATE(absl::StrFormat(
              "Failed reading output from the executable: %s", error_string)));
      return;
    } else {
      if (output_file_path_ != "") {
        std::string output_file_content_string =
            read_file_contents(output_file_path_);
        if (output_file_content_string != "") {
          OnRetrieveSubjectToken();
          return;
        }
      }
      OnRetrieveSubjectToken();
      return;
    }
  } else {
    thr.detach();
    thr.~thread();
    FinishRetrieveSubjectToken(
        "", GRPC_ERROR_CREATE(
                absl::StrFormat("Executable timeout exceeded %d milliseconds.",
                                executable_timeout_ms_)));
    return;
  }
}

void PluggableAuthExternalAccountCredentials::OnRetrieveSubjectToken() {
  // TODO: Fetch gcp token
}

void PluggableAuthExternalAccountCredentials::FinishRetrieveSubjectToken(
    std::string token, grpc_error_handle error) {
  auto cb = cb_;
  cb_ = nullptr;
  error.ok() ? cb(token, absl::OkStatus()) : cb(token, error);
}

}  // namespace grpc_core
