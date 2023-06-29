
//
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

#ifndef GRPC_SRC_CORE_LIB_SECURITY_CREDENTIALS_DOWNSCOPED_DOWNSCOPED_CREDENTIALS_H
#define GRPC_SRC_CORE_LIB_SECURITY_CREDENTIALS_DOWNSCOPED_DOWNSCOPED_CREDENTIALS_H

#include <grpc/support/port_platform.h>

#include "src/core/lib/json/json.h"
#include "src/core/lib/security/credentials/oauth2/oauth2_credentials.h"

namespace grpc_core {
class grpc_downscoped_credentials
    : public grpc_oauth2_token_fetcher_credentials {
 public:
  grpc_call_credentials* source_credential_;
  Json credential_access_boundary_;

  static RefCountedPtr<grpc_downscoped_credentials> Create(
      grpc_call_credentials* source_credential, const Json& json,
      grpc_error_handle* error);

  grpc_downscoped_credentials(grpc_call_credentials* source_credential,
                              const Json& json);
  ~grpc_downscoped_credentials() override;

 private:
  // This method implements the common token fetch logic and it will be called
  // when grpc_oauth2_token_fetcher_credentials request a new access token.
  void fetch_oauth2(grpc_credentials_metadata_request* req,
                    grpc_polling_entity* pollent, grpc_iomgr_cb_func cb,
                    Timestamp deadline) override;
  void on_source_access_token_fetch(std::string access_token);
};

}  // namespace grpc_core

#endif