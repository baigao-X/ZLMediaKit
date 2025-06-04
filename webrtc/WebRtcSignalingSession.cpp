/*
 * Copyright (c) 2016-present The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/ZLMediaKit/ZLMediaKit).
 *
 * Use of this source code is governed by MIT-like license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#include "WebRtcSignalingSession.h"
#include "WebRtcSignalingMsg.h"
#include "WebRtcTransport.h"
#include "Util/util.h"
#include "Common/config.h"
#include "server/WebApi.h"

using namespace std;

namespace mediakit {


//注册上来的peer列表
static ServiceController<WebRtcSignalingSession> s_rooms;

void listWebrtcRooms(const std::function<void(const std::string& key, const WebRtcSignalingSession::Ptr& p)> &cb) {
    s_rooms.for_each(cb);
    return;
}

Json::Value ToJson(const WebRtcSignalingSession::Ptr& p) {
    return p->makeInfoJson();
}

WebRtcSignalingSession::Ptr getWebrtcRoomKeeper(const string &room_id) {
    auto session = s_rooms.find(room_id);
    return session;
}

////////////  WebRtcSignalingSession //////////////////////////

WebRtcSignalingSession::WebRtcSignalingSession(const Socket::Ptr &sock) : Session(sock) {
    DebugL;
}

WebRtcSignalingSession::~WebRtcSignalingSession() {
    DebugL << "room_id: " << _room_id;
};

void WebRtcSignalingSession::onRecv(const Buffer::Ptr &buffer) {
    DebugL << "recv msg:\r\n" << buffer->data();

    Json::Value args;
    Json::Reader reader;
    reader.parse(buffer->data(), args);
    Parser parser;
    HttpAllArgs<decltype(args)> allArgs(parser, args);
    CHECK_ARGS(CLASS_KEY, METHOD_KEY, TRANSACTION_ID_KEY);

    using MsgHandler = void (WebRtcSignalingSession::*)(SIGNALING_MSG_ARGS);
    static std::unordered_map<std::pair<std::string /*class*/, std::string /*method*/>, MsgHandler, ClassMethodHash> s_msg_handlers;

    static onceToken token([]() {
        s_msg_handlers.emplace(std::make_pair(CLASS_VALUE_REQUEST, METHOD_VALUE_REGISTER), &WebRtcSignalingSession::handleRegisterRequest);
        s_msg_handlers.emplace(std::make_pair(CLASS_VALUE_REQUEST, METHOD_VALUE_UNREGISTER), &WebRtcSignalingSession::handleUnregisterRequest);
        s_msg_handlers.emplace(std::make_pair(CLASS_VALUE_REQUEST, METHOD_VALUE_CALL), &WebRtcSignalingSession::handleCallRequest);
        s_msg_handlers.emplace(std::make_pair(CLASS_VALUE_ACCEPT, METHOD_VALUE_CALL), &WebRtcSignalingSession::handleCallAccept);
        s_msg_handlers.emplace(std::make_pair(CLASS_VALUE_REFUSES, METHOD_VALUE_CALL), &WebRtcSignalingSession::handleCallRefuses);
        s_msg_handlers.emplace(std::make_pair(CLASS_VALUE_INDICATION, METHOD_VALUE_BYE), &WebRtcSignalingSession::handleByeIndication);
        s_msg_handlers.emplace(std::make_pair(CLASS_VALUE_INDICATION, METHOD_VALUE_CANDIDATE), &WebRtcSignalingSession::handleCandidateIndication);

        //FIXME:DELETE
        // s_msg_handlers.emplace(METHOD_VALUE_REFUSES, &WebRtcSignalingSession::handleRefuseMsg);

    });

    auto it = s_msg_handlers.find(std::make_pair(allArgs[CLASS_KEY], allArgs[METHOD_KEY]));
    if (it == s_msg_handlers.end()) {
        WarnL << " not support class: "<< allArgs[CLASS_KEY] << ", method: " << allArgs[METHOD_KEY] << ", ignore";
        return;
    }

    return (this->*(it->second))(allArgs);
}

void WebRtcSignalingSession::onError(const SockException &err) {
    WarnL << "room_id: " << _room_id;
    s_rooms.erase(_room_id);
    //除非对端显式的发送了注销执行,否则因为网络异常导致的会话中断，不影响已经进行通信的webrtc会话,仅作移除
    return;
}

void WebRtcSignalingSession::onManager() {
    //Websocket会话会自行定时发送PING/PONG 消息，并进行超时自己管理，该对象暂时不需要心跳超时处理
    return;
}

void WebRtcSignalingSession::handleRegisterRequest(SIGNALING_MSG_ARGS) {
    DebugL;

    CHECK_ARGS(ROOM_ID_KEY);
    Json::Value body;
    body[METHOD_KEY] = METHOD_VALUE_REGISTER;
    body[ROOM_ID_KEY] = allArgs[ROOM_ID_KEY];

    if (s_rooms.find(allArgs[ROOM_ID_KEY])) {
        //已经注册了
        sendRefusesResponse(body, allArgs[TRANSACTION_ID_KEY], "alreadly register");
        return;
    }
    _room_id = allArgs[ROOM_ID_KEY];
    s_rooms.emplace(_room_id, shared_from_this());
    sendRegisterAccept(body, allArgs[TRANSACTION_ID_KEY]);
    return;
};

void WebRtcSignalingSession::handleUnregisterRequest(SIGNALING_MSG_ARGS) {
    DebugL;
    CHECK_ARGS(ROOM_ID_KEY);

    Json::Value body;
    body[METHOD_KEY] = METHOD_VALUE_UNREGISTER;
    body[ROOM_ID_KEY] = allArgs[ROOM_ID_KEY];

    if (allArgs[ROOM_ID_KEY] != getRoomId()) {
        sendRefusesResponse(body, allArgs[TRANSACTION_ID_KEY], StrPrinter << "room_id: \"" << allArgs[ROOM_ID_KEY] << "\" not match room_id:" << getRoomId());
        return;
    }

    sendAcceptResponse(body, allArgs[TRANSACTION_ID_KEY]);

    //同时主动向所有连接的对端会话发送bye
    notifyByeIndication();

    if (s_rooms.find(allArgs[ROOM_ID_KEY])) {
        s_rooms.erase(_room_id);
    }
    return;
};

void WebRtcSignalingSession::handleCallRequest(SIGNALING_MSG_ARGS) {
    DebugL;
    CHECK_ARGS(GUEST_ID_KEY, ROOM_ID_KEY, VHOST_KEY, APP_KEY, STREAM_KEY, TYPE_KEY, SDP_KEY);

    auto session = getWebrtcRoomKeeper(allArgs[ROOM_ID_KEY]);
    if (!session) {
        Json::Value body;
        sendRefusesResponse(body, allArgs[TRANSACTION_ID_KEY], StrPrinter << "room_id: \"" << allArgs[ROOM_ID_KEY] << "\" not register");
        return;
    }
    _tours.emplace(allArgs[GUEST_ID_KEY], allArgs[ROOM_ID_KEY]);

    // forwardOffer
    weak_ptr<WebRtcSignalingSession> sender_ptr = static_pointer_cast<WebRtcSignalingSession>(shared_from_this());
    session->forwardCallRequest(sender_ptr, allArgs);
    return;
};

void WebRtcSignalingSession::handleCallAccept(SIGNALING_MSG_ARGS) {
    DebugL;
    CHECK_ARGS(GUEST_ID_KEY, ROOM_ID_KEY, VHOST_KEY, APP_KEY, STREAM_KEY, SDP_KEY);

    Json::Value body;

    auto it = _guests.find(allArgs[GUEST_ID_KEY]);
    if (it == _guests.end()) {
        WarnL << "guest_id: \"" << allArgs[GUEST_ID_KEY] << "\" not register";
        return;
    }
    auto session = it->second.lock();
    if (!session) {
        WarnL << "guest_id: \"" << allArgs[GUEST_ID_KEY] << "\" leave alreadly";
        return;
    }

    session->forwardCallAccept(allArgs);
    return;
}

void WebRtcSignalingSession::handleByeIndication(SIGNALING_MSG_ARGS) {
    DebugL;
    CHECK_ARGS(GUEST_ID_KEY, ROOM_ID_KEY);
    if (allArgs[ROOM_ID_KEY] == getRoomId()) {
        //作为被叫方,接收bye
        auto it = _guests.find(allArgs[GUEST_ID_KEY]);
        if (it == _guests.end()) {
            WarnL << "guest_id: \"" << allArgs[GUEST_ID_KEY] << "\" not register";
            return;
        }
        auto session = it->second.lock();
        if (!session) {
            WarnL << "guest_id: \"" << allArgs[GUEST_ID_KEY] << "\" leave alreadly";
            return;
        }
        _guests.erase(allArgs[GUEST_ID_KEY]);
        session->forwardBye(allArgs);
        return;
    } else {
        //作为主叫方，接受bye
        auto session = getWebrtcRoomKeeper(allArgs[ROOM_ID_KEY]);
        if (!session) {
            WarnL << "room_id: \"" << allArgs[ROOM_ID_KEY] << "\" not register";
            return;
        }
        _tours.erase(allArgs[GUEST_ID_KEY]);
        session->forwardBye(allArgs);
    }

    return;
}

void WebRtcSignalingSession::handleCandidateIndication(SIGNALING_MSG_ARGS) {
    DebugL;
    CHECK_ARGS(TRANSACTION_ID_KEY, GUEST_ID_KEY, ROOM_ID_KEY, ICE_KEY, UFRAG_KEY, PWD_KEY);
    return handleOtherMsg(allArgs);
}

void WebRtcSignalingSession::handleOtherMsg(SIGNALING_MSG_ARGS) {
    DebugL;
    if (allArgs[ROOM_ID_KEY] == getRoomId()) {
        //作为被叫方,接收bye
        auto it = _guests.find(allArgs[GUEST_ID_KEY]);
        if (it == _guests.end()) {
            WarnL << "guest_id: \"" << allArgs[GUEST_ID_KEY] << "\" not register";
            return;
        }
        auto session = it->second.lock();
        if (!session) {
            WarnL << "guest_id: \"" << allArgs[GUEST_ID_KEY] << "\" leave alreadly";
            return;
        }

        session->forwardPacket(allArgs);
        return;
    } else {
        //作为主叫方，接受bye
        auto session = getWebrtcRoomKeeper(allArgs[ROOM_ID_KEY]);
        if (!session) {
            WarnL << "room_id: \"" << allArgs[ROOM_ID_KEY] << "\" not register";
            return;
        }
        session->forwardPacket(allArgs);
    }
    DebugL << "debug 111";
    return;
}

void WebRtcSignalingSession::notifyByeIndication() {
    DebugL;

    Json::Value allArgs;
    allArgs[CLASS_KEY] = CLASS_VALUE_INDICATION;
    allArgs[METHOD_KEY] = METHOD_VALUE_BYE;
    allArgs[REASON_KEY] = "peer unregister";
    //作为被叫方
    for (auto it : _guests) {
        auto session = it.second.lock();
        if (session) {
            allArgs[TRANSACTION_ID_KEY] = makeRandStr(32);
            allArgs[GUEST_ID_KEY] = it.first;
            allArgs[ROOM_ID_KEY] = getRoomId();
            session->forwardBye(allArgs);
        }
    }

    //作为主叫方
    for (auto it : _tours) {
        auto guest_id = it.first;
        auto peer_room_id = it.second;
        auto session = getWebrtcRoomKeeper(peer_room_id);
        if (session) {
            allArgs[TRANSACTION_ID_KEY] = makeRandStr(32);
            allArgs[GUEST_ID_KEY] = guest_id;
            allArgs[ROOM_ID_KEY] = peer_room_id;
            session->forwardBye(allArgs);
        }
    }

    return;
}

void WebRtcSignalingSession::forwardCallRequest(WebRtcSignalingSession::WeakPtr sender, SIGNALING_MSG_ARGS) {
    DebugL;
    getPoller()->async([=]() {
        _guests.emplace(allArgs[GUEST_ID_KEY], sender);
        sendPacket(allArgs.getArgs());
    });
    return;
}

void WebRtcSignalingSession::forwardCallAccept(SIGNALING_MSG_ARGS) {
    DebugL;
    getPoller()->async([=] (){
        sendPacket(allArgs.getArgs());
    });
    return;
}

void WebRtcSignalingSession::forwardBye(SIGNALING_MSG_ARGS) {
    DebugL;
    getPoller()->async([=]() {
        if (allArgs[ROOM_ID_KEY] == getRoomId()) {
            //作为被叫
            _guests.erase(allArgs[GUEST_ID_KEY]);
        } else {
            //作为主叫
            _tours.erase(allArgs[GUEST_ID_KEY]);
        }
        sendPacket(allArgs.getArgs());
    });
    return;
}

void WebRtcSignalingSession::forwardBye(Json::Value allArgs) {
    DebugL;
    getPoller()->async([=]() {
        if (allArgs[ROOM_ID_KEY] == getRoomId()) {
            //作为被叫
            _guests.erase(allArgs[GUEST_ID_KEY].asString());
        } else {
            //作为主叫
            _tours.erase(allArgs[GUEST_ID_KEY].asString());
        }
        sendPacket(allArgs);
    });
    return;
}

void WebRtcSignalingSession::forwardPacket(SIGNALING_MSG_ARGS) {
    getPoller()->async([=]() {
        sendPacket(allArgs.getArgs());
    });
    return;
}

void WebRtcSignalingSession::sendRegisterAccept(Json::Value& body, const std::string& transaction_id) {
    DebugL;
    body[CLASS_KEY]  = CLASS_VALUE_ACCEPT;

    Json::Value ice_server;
    GET_CONFIG(uint16_t, icePort, Rtc::kIcePort);
    GET_CONFIG(bool, enable_turn, Rtc::kEnableTurn);

    GET_CONFIG_FUNC(std::vector<std::string>, extern_ips, Rtc::kExternIP, [](string str) {
        std::vector<std::string> ret;
        if (str.length()) {
            ret = split(str, ",");
        }
        translateIPFromEnv(ret);
        return ret;
    });

    std::string extern_ip;
    if (extern_ips.empty()) {
        extern_ip = SockUtil::get_local_ip();
    } else {
        extern_ip = extern_ips.front();
    }

    //FIXME: process multi exterm ip

    std::string url;
    //turns:host:port?transport=udp
    //turns:host:port?transport=tcp
    //turn:host:port?transport=udp
    //turn:host:port?transport=tcp
    //stuns:host:port?transport=udp
    //stuns:host:port?transport=udp
    //stun:host:port?transport=tcp
    //stun:host:port?transport=tcp
    if (enable_turn) {
        url = "turn:" + extern_ip + ":" + std::to_string(icePort) + "?transport=udp";
    } else {
        url = "stun:" + extern_ip + ":" + std::to_string(icePort) + "?transport=udp";
    }

    GET_CONFIG(string, iceUfrag, Rtc::kIceUfrag);
    GET_CONFIG(string, icePwd, Rtc::kIcePwd);
    ice_server[URL_KEY] = url;
    ice_server[UFRAG_KEY] = iceUfrag;
    ice_server[PWD_KEY] = icePwd;

    Json::Value ice_servers;
    ice_servers.append(ice_server);

    body[ICE_SERVERS_KEY] = ice_servers;

    //TODO: support multi ice server
    sendAcceptResponse(body, transaction_id);
}

void WebRtcSignalingSession::sendAcceptResponse(Json::Value &body, const std::string& transaction_id) {
    DebugL;
    body[CLASS_KEY] = CLASS_VALUE_ACCEPT;
    sendResponse(body, transaction_id);
}

void WebRtcSignalingSession::sendRefusesResponse(Json::Value &body, const std::string& transaction_id, const std::string& reason) {
    DebugL;
    body[CLASS_KEY] = CLASS_VALUE_REFUSES;
    body[REASON_KEY] = reason;
    sendResponse(body, transaction_id);
}

void WebRtcSignalingSession::sendResponse(Json::Value &body, const std::string& transaction_id) {
    DebugL;
    body[TRANSACTION_ID_KEY] = transaction_id;
    sendPacket(body);
}

void WebRtcSignalingSession::sendPacket(const Json::Value &body) {
    auto msg = body.toStyledString();
    TraceL << "send msg: " << msg;
    SockSender::send(msg);
}

Json::Value WebRtcSignalingSession::makeInfoJson() {
    Json::Value item;
    item["room_id"] = getRoomId();

    Json::Value tours_obj(Json::arrayValue);
    auto tours = _tours;
    for(auto &tour : tours) {
        Json::Value obj;
        obj["guest_id"] = tour.first;
        obj["room_id"] = tour.second;
        tours_obj.append(obj);
    }
    item["tours"] = tours_obj;

    Json::Value guests_obj(Json::arrayValue);
    auto guests = _guests;
    for(auto &guest : guests) {
        Json::Value obj;
        obj["guest_id"] = guest.first;
        guests_obj.append(obj);
    }
    item["guests"] = guests_obj;
    return item;
}

}// namespace mediakit

