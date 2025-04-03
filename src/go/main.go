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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"net/http"
	"syscall/js"
	"time"
)

func verifyCertificateChain() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 3 {
			return "Invalid no of arguments passed"
		}
		certPem := args[0].String()
		subCaPem := args[1].String()
		rootCaPem := args[2].String()

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

				valid := verifyCrl(subCa, rootCa, httpClient)
				if !valid {
					errorObject := errorConstructor.New("Failed to verify intermediate certificate using CRL")
					reject.Invoke(errorObject)
					return
				}

				valid = verifyCrl(rootCa, rootCa, httpClient)
				if !valid {
					errorObject := errorConstructor.New("Failed to verify root certificate using CRL")
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

func verifyCrl(cert *x509.Certificate, issuingCert *x509.Certificate, httpClient *http.Client) bool {
	subCaCrl, err := getCrl(cert, httpClient)
	if err != nil {
		return false
	}
	if err := subCaCrl.CheckSignatureFrom(issuingCert); err != nil {
		return false
	}
	now := time.Now().UTC()
	for _, rev := range subCaCrl.RevokedCertificateEntries {
		if (rev.SerialNumber.Cmp(cert.SerialNumber) == 0) && (rev.RevocationTime.Before(now)) {
			return false
		}
	}
	return true
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

func parseCertificate(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
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

	return ocsp.ParseResponse(responseBody, issuingCert)
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

	return x509.ParseRevocationList(responseBody)
}

func main() {
	fmt.Println("Hello World")
	done := make(<-chan bool)
	js.Global().Set("verifyCertificateChain", verifyCertificateChain())
	<-done
}
