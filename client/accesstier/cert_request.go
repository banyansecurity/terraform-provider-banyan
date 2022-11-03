package accesstier

import (
	"bytes"
	"encoding/base64"
	"errors"
)

// NetagentCertRequest allows Netagents to request a certificate from the
// command center.
type NetagentCertRequest struct {
	// CSR is certificate signing request.
	CSR CASignInfo `json:"csr"`
}

var (
	ErrMissingAccessTierName = errors.New("missing access_tier_name in JSON body")
	ErrMissingCSRID          = errors.New("missing csr ID in JSON body")
	ErrMissingReqPEM         = errors.New("missing csr ReqPEM in JSON body")
)

func (ncr *NetagentCertRequest) Validate() error {
	if ncr.CSR.ID == "" {
		return ErrMissingCSRID
	}

	if ncr.CSR.ReqPEM == "" {
		return ErrMissingReqPEM
	}

	return nil
}

// NetagentCertRequestResponse is the response sent back to Netagent with
// an issued cert for the Netagent to save for use with Shield.
//
// Cluster name is provided for convenience to mirror current Shield secure
// bootstrap behavior on the Netagent.
type NetagentCertRequestResponse struct {
	ClusterName         string `json:"cluster_name"`
	RootCACerts         []byte `json:"root_ca_certs"`
	IntermediateCACerts []byte `json:"intermediate_ca_certs"`
	IssuedCert          []byte `json:"issued_cert"`
}

func allocateCertBuffer(encoder *base64.Encoding, inputLength int) []byte {
	outputLength := encoder.DecodedLen(inputLength)
	outputBuf := make([]byte, outputLength)
	return outputBuf
}

// CACerts is a convenience function. This data canonically consists of root
// and intermediate certificates for authenticating peers.
//
// Decodes B64 encoded certificates to raw bytes.
func (ncrr *NetagentCertRequestResponse) CACertBytes() ([]byte, error) {
	encoder := base64.RawStdEncoding.WithPadding(base64.StdPadding)
	caCerts := append(ncrr.RootCACerts, ncrr.IntermediateCACerts...)
	outputBuf := allocateCertBuffer(encoder, len(caCerts))
	if _, err := encoder.Decode(outputBuf, caCerts); err != nil {
		return nil, err
	}
	return bytes.Trim(outputBuf, "\x00"), nil
}

// IssuedCertBytes decodes (base64) networked value of issued cert.
func (ncrr *NetagentCertRequestResponse) IssuedCertBytes() ([]byte, error) {
	encoder := base64.RawStdEncoding.WithPadding(base64.StdPadding)
	outputBuf := allocateCertBuffer(encoder, len(ncrr.IssuedCert))
	if _, err := encoder.Decode(outputBuf, ncrr.IssuedCert); err != nil {
		return nil, err
	}
	return bytes.Trim(outputBuf, "\x00"), nil
}
