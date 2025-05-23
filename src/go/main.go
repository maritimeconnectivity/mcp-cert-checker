/*
 * Copyright 2025 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ocsp"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"syscall/js"
	"time"
)

const (
	flagState      = "2.25.323100633285601570573910217875371967771"
	callSign       = "2.25.208070283325144527098121348946972755227"
	imoNumber      = "2.25.291283622413876360871493815653100799259"
	mmsiNumber     = "2.25.328433707816814908768060331477217690907"
	aisType        = "2.25.107857171638679641902842130101018412315"
	portOfRegister = "2.25.285632790821948647314354670918887798603"
	shipMrn        = "2.25.268095117363717005222833833642941669792"
	mrn            = "2.25.271477598449775373676560215839310464283"
	permissions    = "2.25.174437629172304915481663724171734402331"
	alternateMrn   = "2.25.133833610339604538603087183843785923701"
	url            = "2.25.245076023612240385163414144226581328607"
)

func verifyCertificateChain() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 3 {
			return "Invalid no of arguments passed"
		}
		certPem := args[0].String()
		subCaPem := args[1].String()
		rootCaPem := args[2].String()

		// required for handling JS Promise
		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve := args[0] // used to fulfill the promise
			reject := args[1]  // used to reject the promise
			errorConstructor := js.Global().Get("Error")

			go func() {
				cert, err := parseCertificate(certPem)
				if err != nil {
					errorObject := errorConstructor.New("Certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				subCa, err := parseCertificate(subCaPem)
				if err != nil {
					errorObject := errorConstructor.New("Intermediate certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				rootCa, err := parseCertificate(rootCaPem)
				if err != nil {
					errorObject := errorConstructor.New("Root certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				subCaPool := x509.NewCertPool()
				subCaPool.AddCert(subCa)

				rootCaPool := x509.NewCertPool()
				rootCaPool.AddCert(rootCa)

				verifyOpts := x509.VerifyOptions{
					Intermediates: subCaPool,
					Roots:         rootCaPool,
				}

				if _, err = cert.Verify(verifyOpts); err != nil {
					errorObject := errorConstructor.New("Certificate chain verification failed")
					reject.Invoke(errorObject)
					return
				}

				httpClient := http.DefaultClient
				err = verifyOcsp(cert, subCa, httpClient)
				if err != nil {
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
					return
				}

				err = verifyCrl(subCa, rootCa, httpClient)
				if err != nil {
					errorObject := errorConstructor.New("Failed to verify intermediate certificate using CRL: " + err.Error())
					reject.Invoke(errorObject)
					return
				}

				err = verifyCrl(rootCa, rootCa, httpClient)
				if err != nil {
					errorObject := errorConstructor.New("Failed to verify root certificate using CRL: " + err.Error())
					reject.Invoke(errorObject)
					return
				}

				resolve.Invoke("Certificate chain verification successful")
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}

func checkOcsp(cert *x509.Certificate, issuingCert *x509.Certificate, httpClient *http.Client) (*ocsp.Response, error) {
	ocspUrl := cert.OCSPServer[0]
	ocspReq, err := ocsp.CreateRequest(cert, issuingCert, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ocsp request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, ocspUrl, bytes.NewReader(ocspReq))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/ocsp-request")

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return nil, fmt.Errorf("failed to close response body: %w", err)
	}

	return ocsp.ParseResponse(responseBody, nil)
}

func verifyOcsp(cert *x509.Certificate, subCa *x509.Certificate, httpClient *http.Client) error {
	ocspResp, err := checkOcsp(cert, subCa, httpClient)
	if err != nil {
		return err
	}
	if err := ocspResp.CheckSignatureFrom(subCa); err != nil {
		return err
	}
	if ocspResp.Status == ocsp.Revoked {
		return fmt.Errorf("certificate is revoked")
	} else if ocspResp.Status == ocsp.Unknown {
		return fmt.Errorf("certificate status is unknown")
	}
	return nil
}

func verifyOcspWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		certPem := args[0].String()
		subCaPem := args[1].String()

		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]
			errorConstructor := js.Global().Get("Error")

			go func() {
				cert, err := parseCertificate(certPem)
				if err != nil {
					errorObject := errorConstructor.New("Certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				subCa, err := parseCertificate(subCaPem)
				if err != nil {
					errorObject := errorConstructor.New("Intermediate certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				if err = verifyOcsp(cert, subCa, http.DefaultClient); err != nil {
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
					return
				}

				resolve.Invoke("OCSP verification successful")
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}

func getCrl(cert *x509.Certificate, httpClient *http.Client) (*x509.RevocationList, error) {
	crlUrl := cert.CRLDistributionPoints[0]
	crlReq, err := http.NewRequest(http.MethodGet, crlUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	crlReq.Header.Set("js.fetch:mode", "cors")

	response, err := httpClient.Do(crlReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return nil, fmt.Errorf("failed to close response body: %w", err)
	}

	crl, _ := pem.Decode(responseBody)
	if crl == nil {
		return nil, fmt.Errorf("failed to PEM decode response body")
	}

	return x509.ParseRevocationList(crl.Bytes)
}

func verifyCrl(cert *x509.Certificate, issuingCert *x509.Certificate, httpClient *http.Client) error {
	crl, err := getCrl(cert, httpClient)
	if err != nil {
		return fmt.Errorf("failed to get CRL: %w", err)
	}
	if err := crl.CheckSignatureFrom(issuingCert); err != nil {
		return fmt.Errorf("failed to verify CRL: %w", err)
	}
	now := time.Now().UTC()
	for _, rev := range crl.RevokedCertificateEntries {
		if (rev.SerialNumber.Cmp(cert.SerialNumber) == 0) && (rev.RevocationTime.Before(now)) {
			return fmt.Errorf("certificate is revoked")
		}
	}
	return nil
}

func verifyCrlWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		certPem := args[0].String()
		subCaPem := args[1].String()

		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]
			errorConstructor := js.Global().Get("Error")

			go func() {
				cert, err := parseCertificate(certPem)
				if err != nil {
					errorObject := errorConstructor.New("Certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				subCa, err := parseCertificate(subCaPem)
				if err != nil {
					errorObject := errorConstructor.New("Intermediate certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				if err := verifyCrl(cert, subCa, http.DefaultClient); err != nil {
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
					return
				}

				resolve.Invoke("CRL verification successful")
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}

func parseCertificate(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCertificateWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 {
			return "Invalid no of arguments passed"
		}
		pemCert := args[0].String()

		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]
			errorConstructor := js.Global().Get("Error")

			go func() {
				cert, err := parseCertificate(pemCert)
				if err != nil {
					errorObject := errorConstructor.New("Certificate parsing failed")
					reject.Invoke(errorObject)
					return
				}

				certificate := Certificate{}

				certificate.cn = cert.Subject.CommonName

				rdns := cert.Subject.Names

				uidOid := []int{0, 9, 2342, 19200300, 100, 1, 1}
				emailUid := []int{1, 2, 840, 113549, 1, 9, 1}
				for _, dn := range rdns {
					if dn.Type.Equal(uidOid) {
						if v, ok := dn.Value.(string); ok {
							certificate.mcpMrn = v
						}
					} else if dn.Type.Equal(emailUid) {
						if v, ok := dn.Value.(string); ok {
							certificate.email = v
						}
					}
				}

				certificate.orgMcpMrn = cert.Subject.Organization[0]
				certificate.country = cert.Subject.Country[0]

				sanOid := []int{2, 5, 29, 17}
				var rawSan []byte
				for _, ext := range cert.Extensions {
					if ext.Id.Equal(sanOid) {
						rawSan = ext.Value
						break
					}
				}

				if len(rawSan) > 0 {
					san := cryptobyte.String(rawSan)

					// Here we just assume that all elements in SAN are OtherNames.
					// Everything that is not, we just skip
					err = forEachSAN(san, func(tag int, data []byte) error {
						on := cryptobyte.String(data)
						var oid cryptobyte.String
						if !on.ReadASN1(&oid, asn1.OBJECT_IDENTIFIER) {
							return nil
						}
						objectIdentifier := parseOid(oid)

						var str cryptobyte.String
						on.ReadASN1(&str, asn1.UTF8String)
						str.ReadASN1(&str, asn1.UTF8String)
						value := string(str)

						switch objectIdentifier {
						case flagState:
							certificate.flagState = value
						case callSign:
							certificate.callSign = value
						case imoNumber:
							certificate.imoNumber = value
						case mmsiNumber:
							certificate.mmsiNumber = value
						case aisType:
							certificate.aisType = value
						case portOfRegister:
							certificate.portOfRegister = value
						case shipMrn:
							certificate.shipMrn = value
						case mrn:
							certificate.mrn = value
						case permissions:
							certificate.permissions = value
						case alternateMrn:
							certificate.mrn = value
						case url:
							certificate.url = value
						}
						return nil
					})
					if err != nil {
						errorObject := errorConstructor.New(err.Error())
						reject.Invoke(errorObject)
						return
					}
				}

				certificate.publicKeyAlgoName = cert.PublicKeyAlgorithm.String()

				pubKey := cert.PublicKey

				switch pubKey.(type) {
				case *ecdsa.PublicKey:
					certificate.publicKeyLength = pubKey.(*ecdsa.PublicKey).Params().BitSize
				}

				certificate.signatureAlgoName = cert.SignatureAlgorithm.String()

				ret := map[string]any{
					"cn":                certificate.cn,
					"mcpMrn":            certificate.mcpMrn,
					"orgMcpMrn":         certificate.orgMcpMrn,
					"email":             certificate.email,
					"country":           certificate.country,
					"flagState":         certificate.flagState,
					"callSign":          certificate.callSign,
					"imoNumber":         certificate.imoNumber,
					"mmsiNumber":        certificate.mmsiNumber,
					"aisType":           certificate.aisType,
					"portOfRegister":    certificate.portOfRegister,
					"shipMrn":           certificate.shipMrn,
					"mrn":               certificate.mrn,
					"permissions":       certificate.permissions,
					"alternateMrn":      certificate.alternateMrn,
					"url":               certificate.url,
					"publicKeyAlgoName": certificate.publicKeyAlgoName,
					"publicKeyLength":   certificate.publicKeyLength,
					"signatureAlgoName": certificate.signatureAlgoName,
				}

				resolve.Invoke(js.ValueOf(ret))
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}

// Copied from x509.forEachSAN
func forEachSAN(der cryptobyte.String, callback func(tag int, data []byte) error) error {
	if !der.ReadASN1(&der, asn1.SEQUENCE) {
		return errors.New("x509: invalid subject alternative names")
	}
	for !der.Empty() {
		var san cryptobyte.String
		var tag asn1.Tag
		if !der.ReadAnyASN1(&san, &tag) {
			return errors.New("x509: invalid subject alternative name")
		}
		if err := callback(int(tag^0x80), san); err != nil {
			return err
		}
	}

	return nil
}

func parseOid(oid cryptobyte.String) string {
	var sb strings.Builder

	firstByte := int64(oid[0])
	sb.WriteString(strconv.FormatInt(firstByte/40, 10))
	sb.WriteRune('.')
	sb.WriteString(strconv.FormatInt(firstByte%40, 10))

	remaining := oid[1:]

	value := big.NewInt(0)
	for _, b := range remaining {
		value.Lsh(value, 7)
		tmp := big.NewInt(0)
		value.Or(value, tmp.And(big.NewInt(int64(b)), big.NewInt(0x7f)))

		if b&0x80 == 0 {
			sb.WriteRune('.')
			sb.WriteString(value.String())
			value = big.NewInt(0)
		}
	}

	return sb.String()
}

func main() {
	fmt.Println("WASM loaded")
	done := make(<-chan bool)
	js.Global().Set("verifyCertificateChain", verifyCertificateChain())
	js.Global().Set("verifyOcsp", verifyOcspWrapper())
	js.Global().Set("verifyCrl", verifyCrlWrapper())
	js.Global().Set("parseCertificate", parseCertificateWrapper())
	<-done
}
