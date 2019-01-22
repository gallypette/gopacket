// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/google/gopacket"
)

// TLSHandshakeRecord defines the structure of a Handskake Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	TLSHandshakeMsgType     uint8
	TLSHandshakeServerHello *serverHelloMsg
	TLSHandshakeClientHello *clientHelloMsg
	TLSHandshakeCertificate *certificateMsg
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	// Switch on Handshake message type
	switch uint8(data[0]) {
	case typeClientHello:
		t.TLSHandshakeMsgType = typeClientHello
		t.TLSHandshakeClientHello = new(clientHelloMsg)
		t.TLSHandshakeClientHello.unmarshal(data)
	case typeServerHello:
		t.TLSHandshakeMsgType = typeServerHello
		t.TLSHandshakeServerHello = new(serverHelloMsg)
		t.TLSHandshakeServerHello.unmarshal(data)
	case typeCertificate:
		t.TLSHandshakeMsgType = typeCertificate
		t.TLSHandshakeCertificate = new(certificateMsg)
		t.TLSHandshakeCertificate.unmarshal(data)
	}
	// Please see the following url if you are interested into implementing the rest:
	// https://golang.org/src/crypto/tls/conn.go?h=readHandshake#L950

	return nil
}
