/*
 * Copyright (c) 2016-present The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/ZLMediaKit/ZLMediaKit).
 *
 * Use of this source code is governed by MIT-like license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */


#ifndef ZLMEDIAKIT_WEBRTC_SIGNALING_MSG_H
#define ZLMEDIAKIT_WEBRTC_SIGNALING_MSG_H

#include "server/WebApi.h"

namespace mediakit {
namespace Rtc {

#define SIGNALING_MSG_ARGS const HttpAllArgs<Json::Value>& allArgs

#define CLASS_KEY               "class"
#define CLASS_VALUE_REQUEST     "request"
#define CLASS_VALUE_INDICATION  "indication" //指示类型,不需要应答
#define CLASS_VALUE_ACCEPT      "accept"     //作为CLASS_VALUE_REQUEST的应答
#define CLASS_VALUE_REFUSES     "refuses"     //作为CLASS_VALUE_REQUEST的应答
#define METHOD_KEY              "method"
#define METHOD_VALUE_REGISTER   "register"
#define METHOD_VALUE_UNREGISTER "unregister"
#define METHOD_VALUE_CALL       "call"
// #define METHOD_VALUE_OFFER      "offer"
// #define METHOD_VALUE_ANSWER     "answer"
#define METHOD_VALUE_BYE        "bye"
#define METHOD_VALUE_CANDIDATE  "candidate"
#define TRANSACTION_ID_KEY      "transaction_id"
#define ROOM_ID_KEY             "room_id"
#define GUEST_ID_KEY            "guest_id"  //每个独立的会话，会拥有一个唯一的guest_id
#define TYPE_KEY                "type"
#define TYPE_VALUE_PLAY         "play"
#define TYPE_VALUE_PUSH         "push"
#define REASON_KEY              "reason"
#define VHOST_KEY               "vhost"
#define APP_KEY                 "app"
#define STREAM_KEY              "stream"
#define SDP_KEY                 "sdp"

#define ICE_SERVERS_KEY         "ice_servers"
#define ICE_KEY                 "ice"
#define URL_KEY                 "url"
#define UFRAG_KEY               "ufrag"
#define PWD_KEY                 "pwd"

} // namespace Rtc
} // namespace mediakit
//

#endif //ZLMEDIAKIT_WEBRTC_SIGNALING_PEER_H
