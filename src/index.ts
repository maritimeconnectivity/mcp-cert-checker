/*
 *  Copyright 2021 Maritime Connectivity Platform Consortium.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
import "bootstrap";
import "bootstrap/dist/css/bootstrap.min.css";

const mrnRegex: RegExp = /^urn:mrn:([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):([a-z0-9][-a-z0-9]{0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/)*)((\?\+((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/|\?)*))?(\?=((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/|\?)*))?)?(#(((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/|\?)*))?$/;
const mcpMrnRegex: RegExp = /^urn:mrn:mcp:(entity|mir|mms|msr|(device|org|user|vessel|service)):([a-z]{2}|([a-z0-9\-._~]|%[0-9a-f][0-9a-f]){3,22}):([a-z0-9\-._~]|%[0-9a-f][0-9a-f]|[!$&'()*+,;=:@])(([a-z0-9\-._~]|%[0-9a-f][0-9a-f]|[!$&'()*+,;=:@])|\/)*$/;

const greenCheckMark: string = "\u2705";
const redCheckMark: string = "\u274C";

const certFileUploader: HTMLInputElement = document.getElementById("certFileUploader") as HTMLInputElement;
const subCaFileUploader: HTMLInputElement = document.getElementById("subCaCertFileUploader") as HTMLInputElement;
const caFileUploader: HTMLInputElement = document.getElementById("caCertFileUploader") as HTMLInputElement;

const submitButton: HTMLButtonElement = document.getElementById("submitBtn") as HTMLButtonElement;
const contentCheckButton: HTMLButtonElement = document.getElementById("contentCheckBtn") as HTMLButtonElement;
const checkOCSPButton: HTMLButtonElement = document.getElementById("ocspBtn") as HTMLButtonElement;
const clearButton: HTMLButtonElement = document.getElementById("clearBtn") as HTMLButtonElement;
const crlButton: HTMLButtonElement = document.getElementById("crlBtn") as HTMLButtonElement;

const textAreas: Array<HTMLTextAreaElement> =
  [
      document.getElementById("certTextArea") as HTMLTextAreaElement,
      document.getElementById("subCaCertTextArea") as HTMLTextAreaElement,
      document.getElementById("caCertTextArea") as HTMLTextAreaElement
  ];

const tableContainer: HTMLDivElement = document.getElementById("tableContainer") as HTMLDivElement;

const certs: Array<string> = new Array<string>(3);

textAreas[0].addEventListener("input", () => {
    const content = textAreas[0].value;
    if (content.length > 0) {
        extractCerts(content);
    }
});

certFileUploader.addEventListener("input", async () => {
    if (certFileUploader.files.length > 0) {
        const file = certFileUploader.files[0];
        let content = await file.text();
        extractCerts(content);
    }
});

textAreas[1].addEventListener("input", () => {
    certs[1] = textAreas[1].value;
});

subCaFileUploader.addEventListener("input", async () => {
    if (subCaFileUploader.files.length > 0) {
        const file = subCaFileUploader.files[0];
        const content = await file.text();
        certs[1] = content;
        textAreas[1].value = content;
    }
});

textAreas[2].addEventListener("input", () => {
    certs[2] = textAreas[2].value;
});

caFileUploader.addEventListener("input", async () => {
    if (caFileUploader.files.length > 0) {
        const file = caFileUploader.files[0];
        const content = await file.text();
        certs[2] = content;
        textAreas[2].value = content;
    }
});

submitButton.addEventListener("click", () => {
    verifyCertificateChain(certs[0], certs[1], certs[2])
      .then(result => alert(result))
      .catch(error => alert(error));
});

contentCheckButton.addEventListener("click", () => {
    parseCertificate(certs[0])
      .then(c => validateCertContent(c))
      .catch(error => alert(error));
});

checkOCSPButton.addEventListener("click", () => {
    verifyOcsp(certs[0], certs[1])
      .then(result => alert(result))
      .catch(error => alert(error));
});

crlButton.addEventListener("click", async () => {
    verifyCrl(certs[0], certs[1])
      .then(result => alert(result))
      .catch(error => alert(error));
});

clearButton.addEventListener("click", () => {
    location.reload();
});

function extractCerts(pemCerts: string): void {
    let matches = [...pemCerts.matchAll(/(-----BEGIN CERTIFICATE-----)(.*?)(-----END CERTIFICATE-----)/smg)];
    matches.forEach((m, i) => {
        certs[i] = m[0];
        textAreas[i].value = certs[i];
    });
}

function validateCertContent(certificate: Certificate): void {
    const cn = certificate.cn; // CN
    const cnRow: HTMLTableRowElement = document.getElementById("CN") as HTMLTableRowElement;
    if (cn) {
        cnRow.cells[1].textContent = cn;
        cnRow.cells[2].textContent = greenCheckMark;
    } else {
        cnRow.cells[2].textContent = redCheckMark;
        cnRow.cells[2].title = "CN cannot be empty";
    }

    const mcpMrn = certificate.mcpMrn; // UID
    const uidRow: HTMLTableRowElement = document.getElementById("UID") as HTMLTableRowElement;
    if (mcpMrn && isValidMcpMRN(mcpMrn)) {
        uidRow.cells[1].textContent = mcpMrn;
        uidRow.cells[2].textContent = greenCheckMark;
    } else {
        uidRow.cells[2].textContent = redCheckMark;
        uidRow.cells[2].title = "Entity MRN is not a valid MCP MRN";
    }

    const orgMcpMrn = certificate.orgMcpMrn; // O
    const oRow: HTMLTableRowElement = document.getElementById("O") as HTMLTableRowElement;
    if (orgMcpMrn && isValidMcpMRN(orgMcpMrn)) {
        oRow.cells[1].textContent = orgMcpMrn;
        oRow.cells[2].textContent = greenCheckMark;
    } else {
        oRow.cells[2].textContent = redCheckMark;
        oRow.cells[2].title = "Organization MRN is not a valid MCP MRN";
    }
    const email = certificate.email; // E
    const emailRow: HTMLTableRowElement = document.getElementById("E") as HTMLTableRowElement;
    if (email) {
        emailRow.cells[1].textContent = email;
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            emailRow.cells[2].textContent = redCheckMark;
            emailRow.cells[2].title = "The email address in the certificate is not valid";
        } else {
            emailRow.cells[2].textContent = greenCheckMark;
        }
    }

    const mrnSplit = mcpMrn.split(":");

    const orgMrnSplit = orgMcpMrn.split(":");
    if ((mrnSplit[4] !== orgMrnSplit[4]) || (mrnSplit[5] !== orgMrnSplit[5])) {
        uidRow.cells[2].textContent = oRow.cells[2].textContent = redCheckMark;
        uidRow.cells[2].title = oRow.cells[2].title = "Information in entity MRN does not correspond with information in organization MRN";
    }

    const country = certificate.country; // C
    const cRow: HTMLTableRowElement = document.getElementById("C") as HTMLTableRowElement;
    if (country) {
        cRow.cells[1].textContent = country;
        cRow.cells[2].textContent = greenCheckMark;
    } else {
        cRow.cells[2].textContent = redCheckMark;
        cRow.cells[2].title = "Country is not included in the certificate";
    }

    const flagState = certificate.flagState;
    if (flagState) {
        const flagStateRow: HTMLTableRowElement = document.getElementById("flagstate") as HTMLTableRowElement;
        flagStateRow.cells[1].textContent = flagState;
        flagStateRow.cells[2].textContent = greenCheckMark;
    }

    const callSign = certificate.callSign;
    if (callSign) {
        const callSignRow: HTMLTableRowElement = document.getElementById("callsign") as HTMLTableRowElement;
        callSignRow.cells[1].textContent = callSign;
        callSignRow.cells[2].textContent = greenCheckMark;
    }

    const portOfRegister = certificate.portOfRegister;
    if (portOfRegister) {
        const portOfRegisterRow: HTMLTableRowElement = document.getElementById("port") as HTMLTableRowElement;
        portOfRegisterRow.cells[1].textContent = portOfRegister;
        portOfRegisterRow.cells[2].textContent = greenCheckMark;
    }

    const imoNumber = certificate.imoNumber;
    if (imoNumber) {
        const imoRow: HTMLTableRowElement = document.getElementById("imo") as HTMLTableRowElement;
        imoRow.cells[1].textContent = imoNumber;
        if (!/^(IMO)?( )?\d{7}$/.test(imoNumber)) {
            imoRow.cells[2].textContent = redCheckMark;
            imoRow.cells[2].title = "The IMO number is not valid";
        } else {
            imoRow.cells[2].textContent = greenCheckMark;
        }
    }

    const mmsiNumber = certificate.mmsiNumber;
    if (mmsiNumber) {
        const mmsiRow: HTMLTableRowElement = document.getElementById("mmsi") as HTMLTableRowElement;
        mmsiRow.cells[1].textContent = mmsiNumber;
        if (!/^\d{9}$/.test(mmsiNumber)) {
            mmsiRow.cells[2].textContent = redCheckMark;
            mmsiRow.cells[2].title = "The MMSI number is not valid";
        } else {
            mmsiRow.cells[2].textContent = greenCheckMark;
        }
    }

    const aisType = certificate.aisType;
    if (aisType) {
        const aisTypeRow: HTMLTableRowElement = document.getElementById("ais") as HTMLTableRowElement;
        aisTypeRow.cells[1].textContent = aisType;
        if (!/^[AB]$/.test(aisType)) {
            aisTypeRow.cells[2].textContent = redCheckMark;
            aisTypeRow.cells[2].title = "The AIS type is not valid";
        } else {
            aisTypeRow.cells[2].textContent = greenCheckMark;
        }
    }

    const shipMrn = certificate.shipMrn;
    if (shipMrn) {
        const shipMrnRow: HTMLTableRowElement = document.getElementById("shipMrn") as HTMLTableRowElement;
        shipMrnRow.cells[1].textContent = shipMrn;
        if (!isValidMcpMRN(shipMrn)) {
            shipMrnRow.cells[2].textContent = redCheckMark;
            shipMrnRow.cells[2].title = "Ship MRN is not a valid MCP MRN";
        } else {
            shipMrnRow.cells[2].textContent = greenCheckMark;
        }
    }

    const mrn = certificate.mrn;
    if (mrn) {
        const mrnRow: HTMLTableRowElement = document.getElementById("mrn") as HTMLTableRowElement;
        mrnRow.cells[1].textContent = mrn;
        if (!isValidMcpMRN(mrn) || mrn !== mcpMrn) {
            mrnRow.cells[2].textContent = redCheckMark;
            mrnRow.cells[2].title = "The MRN field is either not a valid MCP MRN or not equal to the UID";
        } else {
            mrnRow.cells[2].textContent = greenCheckMark;
        }
    }

    const permissions = certificate.permissions;
    if (permissions) {
        const permissionRow: HTMLTableRowElement = document.getElementById("permissions") as HTMLTableRowElement;
        permissionRow.cells[1].textContent = permissions;
        permissionRow.cells[2].textContent = greenCheckMark;
    }

    const alternateMrn = certificate.alternateMrn;
    if (alternateMrn) {
        const subMrnRow: HTMLTableRowElement = document.getElementById("alternateMrn") as HTMLTableRowElement;
        subMrnRow.cells[1].textContent = alternateMrn;
        if (alternateMrn === mcpMrn || !isValidMRN(alternateMrn)) {
            subMrnRow.cells[2].textContent = redCheckMark;
            subMrnRow.cells[2].title = "Subsidiary MRN is either the same as primary MRN or not a valid MRN";
        } else {
            subMrnRow.cells[2].textContent = greenCheckMark;
        }
    }

    const url = certificate.url;
    if (url) {
        const urlRow: HTMLTableRowElement = document.getElementById("url") as HTMLTableRowElement;
        urlRow.cells[1].textContent = url;
        if (!isValidURL(url)) {
            urlRow.cells[2].textContent = redCheckMark;
            urlRow.cells[2].title = "MMS URL is not valid";
        } else {
            urlRow.cells[2].textContent = greenCheckMark;
        }
    }

    if (certificate.publicKeyAlgoName !== "ECDSA") {
        alert("The certificate is not using an MCC endorsed public key algorithm");
    }

    const pubKeyLength = certificate.publicKeyLength;
    if (pubKeyLength !== 256 && pubKeyLength !== 384) {
        alert("The certificate is not using an MCC endorsed public key length");
    }

    const signatureAlgorithm = certificate.signatureAlgoName;
    if ((pubKeyLength == 256 && signatureAlgorithm !== "ECDSA-SHA256") || (pubKeyLength == 384 && signatureAlgorithm !== "ECDSA-SHA384")) {
        alert("The certificate is not using an MCC endorsed signature algorithm");
    }

    tableContainer.hidden = false;
}

function isValidMRN(mrn: string): boolean {
    return mrnRegex.test(mrn);
}

function isValidMcpMRN(mrn: string): boolean {
    return isValidMRN(mrn) && mcpMrnRegex.test(mrn);
}

function isValidURL(url: string): boolean {
    try {
        new URL(url);
    } catch {
        return false;
    }
    return true;
}
