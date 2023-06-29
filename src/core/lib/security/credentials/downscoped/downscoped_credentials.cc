
// Copyright 2020 gRPC authors.
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

#include "src/core/lib/security/credentials/downscoped/downscoped_credentials.h"

#include <stdint.h>
#include <string.h>

#include "downscoped_credentials.h"

#include <grpc/grpc.h>
#include <grpc/grpc_security.h>
#include <grpc/support/alloc.h>
#include <grpc/support/json.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>

#include "src/core/lib/json/json_reader.h"
#include "src/core/lib/json/json_writer.h"
#include "src/core/lib/promise/exec_ctx_wakeup_scheduler.h"
#include "src/core/lib/promise/promise.h"
#include "src/core/lib/promise/seq.h"
#include "src/core/lib/security/util/json_util.h"

namespace grpc_core {
// grpc_downscoped_credentials::grpc_downscoped_credentials(
//     grpc_call_credentials* source_credential, const Json& json)
//     : source_credential_(std::move(source_credential)) {
//   credential_access_boundary_ = std::move(json);
// }
RefCountedPtr<grpc_downscoped_credentials> grpc_downscoped_credentials::Create(
    grpc_call_credentials* source_credentials, const Json& cab_json,
    grpc_error_handle* error) {
  RefCountedPtr<grpc_downscoped_credentials> creds;
  creds = MakeRefCounted<grpc_downscoped_credentials>(
      std::move(source_credentials), std::move(cab_json));
  return creds;
}

grpc_downscoped_credentials::grpc_downscoped_credentials(
    grpc_call_credentials* source_credentials, const Json& cab_json) {
  source_credential_ = std::move(source_credentials);
  credential_access_boundary_ = std::move(cab_json);
}
grpc_downscoped_credentials::~grpc_downscoped_credentials() {}

void grpc_downscoped_credentials::fetch_oauth2(
    grpc_credentials_metadata_request* metadata_req,
    grpc_polling_entity* pollent, grpc_iomgr_cb_func response_cb,
    Timestamp deadline) {
  grpc_error_handle error;
  auto creds = source_credential_;
  auto s = Seq(creds->GetRequestMetadata(
          GetContext<Arena>()->MakePooled<ClientMetadata>(GetContext<Arena>()),
          nullptr),
      [this](absl::StatusOr<ClientMetadataHandle> metadata) {
        std::cout << "In second promise!\n";
        return metadata;
      });
  // auto r = p();
  // r.ready() ? std::cout << "Ready!\n" : std::cout << "Not Ready!\n";
  std::cout << "Exiting downscoped credentials fetch_oauth2!\n";
  // grpc_polling_entity pollent_ = *pollent;
  // auto self = Ref();
  // auto activity = MakeActivity(
  //     [this, creds] {
  //       return Seq(creds->GetRequestMetadata(
  //                      GetContext<Arena>()->MakePooled<ClientMetadata>(
  //                          GetContext<Arena>()),
  //                      nullptr),
  //                  [this](absl::StatusOr<ClientMetadataHandle> metadata) {
  //                    std::cout << "In second promise!\n";
  //                    return metadata;
  //                  });
  //     },
  //     ExecCtxWakeupScheduler(),
  //     [self](absl::StatusOr<ClientMetadataHandle> metadata) mutable {
  //       std::cout<<"In Call Back\n";
  //     },
  //     GetContext<Arena>(), &pollent_);
}

void grpc_downscoped_credentials::on_source_access_token_fetch(
    std::string access_token) {
  std::cout << "Access token from metadata:\n" << access_token;
}

}  // namespace grpc_core

grpc_call_credentials* grpc_downscoped_credentials_create(
    grpc_call_credentials* source_creds, const char* cab_json_string) {
  std::cout << "Creating Downscoped Credentials!\n";
  auto cab_json = grpc_core::JsonParse(cab_json_string);
  grpc_error_handle error;
  auto creds = grpc_core::grpc_downscoped_credentials::Create(source_creds,
                                                              *cab_json, &error)
                   .release();
  return creds;
}