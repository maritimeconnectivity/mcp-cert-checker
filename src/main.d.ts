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

interface Certificate {
    cn?: string,
    mcpMrn?: string,
    orgMcpMrn?: string,
    email?: string,
    country?: string,
    flagState?: string,
    callSign?: string,
    imoNumber?: string,
    mmsiNumber?: string,
    aisType?: string,
    portOfRegister?: string,
    shipMrn?: string,
    altNameMrn?: string,
    permissions?: string,
    subMrn?: string,
    url?: string,
}

declare function verifyCertificateChain(cert: string, intermediateCert: string, rootCert: string): Promise<string>;

declare function verifyOcsp(cert: string, intermediateCert: string): Promise<string>;

declare function verifyCrl(cert: string, intermediateCert: string): Promise<string>;

declare function parseCertificate(cert: string): Promise<Certificate>;
