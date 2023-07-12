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
#include <future>
#include <initializer_list>
#include <iostream>
#include <map>
#include <memory>
#include <thread>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"

#include <grpc/support/json.h>

#include "src/core/lib/gpr/subprocess.h"
#include "src/core/lib/json/json.h"
#include "src/core/lib/security/credentials/external/external_account_credentials.h"

#define DEFAULT_EXECUTABLE_TIMEOUT_MS 30000  // 30 seconds
#define MIN_EXECUTABLE_TIMEOUT_MS 5000       // 5 seconds
#define MAX_EXECUTABLE_TIMEOUT_MS 120000     // 120 seconds

std::string read_file_contents(std::string output_file_path) {
  std::string content = "", line;
  std::ifstream output_file(output_file_path);
  if (output_file.is_open()) {
    while (getline(output_file, line)) {
      absl::StrAppend(&content, line);
    }
  }
  return content;
}

std::string get_impersonated_email(
    std::string service_account_impersonation_url) {
  std::vector<absl::string_view> url_elements =
      absl::StrSplit(service_account_impersonation_url, "/");
  absl::string_view impersonated_email;
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

void PluggableAuthExternalAccountCredentials::RetrieveSubjectToken(
    HTTPRequestContext* /*ctx*/, const Options& /*options*/,
    std::function<void(std::string, grpc_error_handle)> cb) {
  cb_ = cb;
  if (output_file_path_ != "") {
    std::string output_file_content_string =
        read_file_contents(output_file_path_);
    if (output_file_content_string != "") {
      OnRetrieveSubjectToken(output_file_content_string);
      return;
    }
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
  std::string output, error;
  std::thread thr(std::move(run_executable_task), subprocess, command_, envp,
                  &output, &error);
  if (executable_output_future.wait_for(std::chrono::seconds(
          executable_timeout_ms_ / 1000)) != std::future_status::timeout) {
    thr.join();
    if (!executable_output_future.get()) {
      FinishRetrieveSubjectToken(
          "", GRPC_ERROR_CREATE(absl::StrFormat(
                  "Failed reading output from the executable: %s", error)));
      return;
    } else {
      if (output_file_path_ != "") {
        std::string output_file_content_string =
            read_file_contents(output_file_path_);
        if (output_file_content_string != "") {
          OnRetrieveSubjectToken(output_file_content_string);
          return;
        }
      }
      OnRetrieveSubjectToken(output);
      return;
    }
  } else {
    thr.detach();
    FinishRetrieveSubjectToken(
        "", GRPC_ERROR_CREATE(
                absl::StrFormat("Executable timeout exceeded %d milliseconds.",
                                executable_timeout_ms_)));
    return;
  }
}

void PluggableAuthExternalAccountCredentials::OnRetrieveSubjectToken(
    std::string executable_output) {
  std::cout << executable_output << "\n";
  // TODO: Parse Response
}

void PluggableAuthExternalAccountCredentials::FinishRetrieveSubjectToken(
    std::string token, grpc_error_handle error) {
  auto cb = cb_;
  cb_ = nullptr;
  error.ok() ? cb(token, absl::OkStatus()) : cb(token, error);
}

}  // namespace grpc_core
