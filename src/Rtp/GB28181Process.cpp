﻿/*
 * Copyright (c) 2016-present The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/ZLMediaKit/ZLMediaKit).
 *
 * Use of this source code is governed by MIT-like license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#if defined(ENABLE_RTPPROXY)
#include "GB28181Process.h"
#include "Extension/CommonRtp.h"
#include "Extension/Factory.h"
#include "Http/HttpTSPlayer.h"
#include "Util/File.h"
#include "Common/config.h"
#include "Rtsp/RtpReceiver.h"
#include "Rtsp/Rtsp.h"

using namespace std;
using namespace toolkit;

namespace mediakit {

// 判断是否为ts负载  [AUTO-TRANSLATED:77d1aa3c]
// Determine if it is a ts payload
static inline bool checkTS(const uint8_t *packet, size_t bytes) {
    return bytes % TS_PACKET_SIZE == 0 && packet[0] == TS_SYNC_BYTE;
}

class RtpReceiverImp : public RtpTrackImp {
public:
    using Ptr = std::shared_ptr<RtpReceiverImp>;

    RtpReceiverImp(int sample_rate, RtpTrackImp::OnSorted cb, RtpTrackImp::BeforeSorted cb_before = nullptr) {
        _sample_rate = sample_rate;
        setOnSorted(std::move(cb));
        setBeforeSorted(std::move(cb_before));
        // GB28181推流不支持ntp时间戳  [AUTO-TRANSLATED:f661f052]
        // GB28181 streaming does not support ntp timestamps
        setNtpStamp(0, 0);
    }

    bool inputRtp(TrackType type, uint8_t *ptr, size_t len) {
        return RtpTrack::inputRtp(type, _sample_rate, ptr, len).operator bool();
    }

private:
    int _sample_rate;
};

///////////////////////////////////////////////////////////////////////////////////////////

GB28181Process::GB28181Process(const MediaInfo &media_info, MediaSinkInterface *sink) {
    assert(sink);
    _media_info = media_info;
    _interface = sink;
}

void GB28181Process::onRtpSorted(RtpPacket::Ptr rtp) {
    _rtp_decoder[rtp->getHeader()->pt]->inputRtp(rtp, false);
}

void GB28181Process::flush() {
    if (_decoder) {
        _decoder->flush();
    }
}

bool GB28181Process::inputRtp(bool, const char *data, size_t data_len) {
    GET_CONFIG(uint32_t, h264_pt, RtpProxy::kH264PT);
    GET_CONFIG(uint32_t, h265_pt, RtpProxy::kH265PT);
    GET_CONFIG(uint32_t, ps_pt, RtpProxy::kPSPT);
    GET_CONFIG(uint32_t, opus_pt, RtpProxy::kOpusPT);

    RtpHeader *header = (RtpHeader *)data;
    auto pt = header->pt;
    auto &ref = _rtp_receiver[pt];
    if (!ref) {
        if (_rtp_receiver.size() > 2) {
            // 防止pt类型太多导致内存溢出  [AUTO-TRANSLATED:7695e49b]
            // Prevent too many pt types from causing memory overflow
            WarnL << "Rtp payload type more than 2 types: " << _rtp_receiver.size();
        }

        do {
            if (pt < 96) {
                auto codec = RtpPayload::getCodecId(pt);
                if (codec != CodecInvalid && codec != CodecTS) {
                    auto sample_rate = RtpPayload::getClockRate(pt);
                    auto channels = RtpPayload::getAudioChannel(pt);
                    ref = std::make_shared<RtpReceiverImp>(sample_rate, [this](RtpPacket::Ptr rtp) { onRtpSorted(std::move(rtp)); });
                    auto track = Factory::getTrackByCodecId(codec, sample_rate, channels);
                    CHECK(track);
                    track->setIndex(pt);
                    _interface->addTrack(track);
                    _rtp_decoder[pt] = Factory::getRtpDecoderByCodecId(track->getCodecId());
                    break;
                }
            }
            if (pt == opus_pt) {
                // opus负载  [AUTO-TRANSLATED:defa6a8d]
                // opus payload
                ref = std::make_shared<RtpReceiverImp>(48000, [this](RtpPacket::Ptr rtp) { onRtpSorted(std::move(rtp)); });
                auto track = Factory::getTrackByCodecId(CodecOpus);
                CHECK(track);
                track->setIndex(pt);
                _interface->addTrack(track);
                _rtp_decoder[pt] = Factory::getRtpDecoderByCodecId(track->getCodecId());
                break;
            }
            if (pt == h265_pt) {
                // H265负载  [AUTO-TRANSLATED:61fbcf7f]
                // H265 payload
                ref = std::make_shared<RtpReceiverImp>(90000, [this](RtpPacket::Ptr rtp) { onRtpSorted(std::move(rtp)); });
                auto track = Factory::getTrackByCodecId(CodecH265);
                CHECK(track);
                track->setIndex(pt);
                _interface->addTrack(track);
                _rtp_decoder[pt] = Factory::getRtpDecoderByCodecId(track->getCodecId());
                break;
            }
            if (pt == h264_pt) {
                // H264负载  [AUTO-TRANSLATED:6f3fbb0d]
                // H264 payload
                ref = std::make_shared<RtpReceiverImp>(90000, [this](RtpPacket::Ptr rtp) { onRtpSorted(std::move(rtp)); });
                auto track = Factory::getTrackByCodecId(CodecH264);
                CHECK(track);
                track->setIndex(pt);
                _interface->addTrack(track);
                _rtp_decoder[pt] = Factory::getRtpDecoderByCodecId(track->getCodecId());
                break;
            }

            if (pt != Rtsp::PT_MP2T && pt != ps_pt) {
                WarnL << "Unknown rtp payload type(" << (int)pt << "), decode it as mpeg-ps or mpeg-ts";
            }
            ref = std::make_shared<RtpReceiverImp>(90000, [this](RtpPacket::Ptr rtp) { onRtpSorted(std::move(rtp)); });
            // ts或ps负载  [AUTO-TRANSLATED:3ca31480]
            // ts or ps payload
            _rtp_decoder[pt] = std::make_shared<CommonRtpDecoder>(CodecInvalid, 32 * 1024);
            // 设置dump目录  [AUTO-TRANSLATED:23c88ace]
            // Set dump directory
            GET_CONFIG(string, dump_dir, RtpProxy::kDumpDir);
            if (!dump_dir.empty()) {
                auto save_path = File::absolutePath(_media_info.stream + ".mpeg", dump_dir);
                _save_file_ps.reset(File::create_file(save_path.data(), "wb"), [](FILE *fp) {
                    if (fp) {
                        fclose(fp);
                    }
                });
            }
        } while (false);

        // 设置frame回调  [AUTO-TRANSLATED:dec7590f]
        // Set frame callback
        _rtp_decoder[pt]->addDelegate([this, pt](const Frame::Ptr &frame) {
            frame->setIndex(pt);
            onRtpDecode(frame);
            return true;
        });
    }

    return ref->inputRtp(TrackVideo, (unsigned char *)data, data_len);
}

void GB28181Process::onRtpDecode(const Frame::Ptr &frame) {
    switch (frame->getCodecId()) {
        case CodecInvalid:
        case CodecTS:
        case CodecPS: break;

        default:
            // 这里不是ps或ts  [AUTO-TRANSLATED:6f79ac69]
            // This is not ps or ts
            _interface->inputFrame(frame);
            return;
    }

    // 这是TS或PS  [AUTO-TRANSLATED:55782860]
    // This is TS or PS
    if (_save_file_ps) {
        fwrite(frame->data(), frame->size(), 1, _save_file_ps.get());
    }

    if (!_decoder) {
        // 创建解码器  [AUTO-TRANSLATED:0cc03d90]
        // Create decoder
        if (checkTS((uint8_t *)frame->data(), frame->size())) {
            // 猜测是ts负载  [AUTO-TRANSLATED:c2be3a47]
            // Guess it is a ts payload
            InfoL << _media_info.stream << " judged to be TS";
            _decoder = DecoderImp::createDecoder(DecoderImp::decoder_ts, _interface);
        } else {
            // 猜测是ps负载  [AUTO-TRANSLATED:b7c0ff45]
            // Guess it is a ps payload
            InfoL << _media_info.stream << " judged to be PS";
            _decoder = DecoderImp::createDecoder(DecoderImp::decoder_ps, _interface);
        }
    }

    if (_decoder) {
        _decoder->input(reinterpret_cast<const uint8_t *>(frame->data()), frame->size());
    }
}

} // namespace mediakit
#endif // defined(ENABLE_RTPPROXY)
