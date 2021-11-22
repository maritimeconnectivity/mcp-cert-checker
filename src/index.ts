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
import 'bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import Asn1js, {fromBER, LocalBaseBlock, LocalSidValueBlock} from "asn1js";
import Certificate from "pkijs/src/Certificate";
import CertificateChainValidationEngine from "pkijs/src/CertificateChainValidationEngine";
import OCSPRequest from "pkijs/src/OCSPRequest";
import InfoAccess from "pkijs/src/InfoAccess";
import OCSPResponse from "pkijs/src/OCSPResponse";
import CRLDistributionPoints from "pkijs/src/CRLDistributionPoints";
import CertificateRevocationList from "pkijs/src/CertificateRevocationList";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import GeneralName from "pkijs/src/GeneralName";
import ECPublicKey from "pkijs/src/ECPublicKey";

interface Asn1Struct {
    offset: number,
    result: LocalBaseBlock
}

interface McpAltNameAttribute {
    oid: string,
    value: string
}

interface ValidationResult {
    valid: boolean,
    error: string
}

const mrnRegex: RegExp = /^urn:mrn:([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):([a-z0-9][-a-z0-9]{0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/)*)((\?\+((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/|\?)*))?(\?=((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/|\?)*))?)?(#(((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/|\?)*))?$/;
const mcpMrnRegex: RegExp = /^urn:mrn:mcp:(device|org|user|vessel|service|mms):([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/)*)$/;
const mcpTypes: Array<string> = ["device", "org", "user", "vessel", "service", "mms"];

const certFileUploader: HTMLInputElement = document.getElementById('certFileUploader') as HTMLInputElement;
const subCaFileUploader: HTMLInputElement = document.getElementById('subCaCertFileUploader') as HTMLInputElement;
const caFileUploader: HTMLInputElement = document.getElementById('caCertFileUploader') as HTMLInputElement;

const submitButton: HTMLButtonElement = document.getElementById('submitBtn') as HTMLButtonElement;
const contentCheckButton: HTMLButtonElement = document.getElementById('contentCheckBtn') as HTMLButtonElement;
const checkOCSPButton: HTMLButtonElement = document.getElementById('ocspBtn') as HTMLButtonElement;
const clearButton: HTMLButtonElement = document.getElementById('clearBtn') as HTMLButtonElement;
const crlButton: HTMLButtonElement = document.getElementById('crlBtn') as HTMLButtonElement;

const textAreas: Array<HTMLTextAreaElement> =
    [
        document.getElementById('certTextArea') as HTMLTextAreaElement,
        document.getElementById('subCaCertTextArea') as HTMLTextAreaElement,
        document.getElementById('caCertTextArea') as HTMLTextAreaElement
    ];

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

submitButton.addEventListener("click", async () => {
    const parsedCerts: Array<Certificate> = certs.map(parseCertificate);
    const ocspResponse = await getOCSP(parsedCerts[0], parsedCerts[1]);
    const crls = await Promise.all(parsedCerts.slice(0,2).map(getCRL));
    const validationEngine: CertificateChainValidationEngine = new CertificateChainValidationEngine(
        {
            certs: parsedCerts.slice(0, parsedCerts.length - 1),
            trustedCerts: [parsedCerts[2]],
            ocsps: [ocspResponse],
            crls: crls
        });
    validationEngine.verify().then(r => {
        if (r?.result) {
            alert("The trust chain was successfully verified!");
        } else {
            alert("The trust chain could not be verified!");
        }
    }, () => alert("This was bad!"));
});

contentCheckButton.addEventListener("click", () => {
   const cert: Certificate = parseCertificate(certs[0]);
   if (cert) {
       let certValidationResult = validateCertContent(cert);
       if (!certValidationResult.valid) {
           alert(`Certificate content could not be validated.\n${certValidationResult.error}`);
       } else {
           alert("Certificate content was validated successfully.");
       }
   } else {
       alert("No certificate was found");
   }
});

checkOCSPButton.addEventListener("click", async () => {
    const parsedCerts: Array<Certificate> = certs.map(parseCertificate);

    const ocspResponse = await getOCSP(parsedCerts[0], parsedCerts[1]);
    const status = await ocspResponse.getCertificateStatus(parsedCerts[0], parsedCerts[1]);

    let message;
    switch (status.status) {
        case 0:
            message = 'The certificate is valid.';
            break;
        case 1:
            message = 'The certificate has been revoked.';
            break;
        case 2:
            message = 'The revocation status of the certificate could not be determined.';
            break;
    }
    alert(message);
});

crlButton.addEventListener("click", async () => {
    const parsedCerts: Array<Certificate> = certs.map(parseCertificate);

    const crl = await getCRL(parsedCerts[0]);
    if (await crl.verify({issuerCertificate: parsedCerts[1]})) {
        if (crl.isCertificateRevoked(parsedCerts[0])) {
            alert("The certificate has been revoked.");
        } else {
            alert("The certificate is valid.");
        }
    } else {
        alert("The CRL could not be verified.");
    }
});

clearButton.addEventListener("click", () => {
   location.reload();
});

function parsePem(input: string): Asn1Struct {
    const b64 = input.replace(/(-----(BEGIN|END) (.*?)-----|[\n\r])/g, '');
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return fromBER(bytes.buffer);
}

function parseCertificate(pemCert: string): Certificate {
    const asn1 = parsePem(pemCert);
    return new Certificate({ schema: asn1.result });
}

function extractCerts(pemCerts: string): void {
    let matches = [...pemCerts.matchAll(/(-----BEGIN CERTIFICATE-----)(.*?)(-----END CERTIFICATE-----)/smg)];
    matches.forEach((m, i) => {
       certs[i] = m[0];
       textAreas[i].value = certs[i];
    });
}

async function getOCSP(certificate: Certificate, issuerCertificate: Certificate): Promise<OCSPResponse> {
    const ocspReq: OCSPRequest = new OCSPRequest();

    await ocspReq.createForCertificate(certificate, { hashAlgorithm: "SHA-384", issuerCertificate: issuerCertificate} );
    const ocsp = ocspReq.toSchema(true) as Asn1js.Sequence;
    const tmp = certificate.extensions.find(e => e.extnID === "1.3.6.1.5.5.7.1.1").parsedValue as InfoAccess;
    const ocspUrl = tmp.accessDescriptions[0].accessLocation.value;
    const encodedOcsp = encodeURIComponent(btoa(String.fromCharCode(...new Uint8Array(ocsp.toBER()))));
    const response = await fetch(`${ocspUrl}/${encodedOcsp}`, {
        mode: "cors",
        cache: "no-cache"
    });
    const rawOcspResponse = await (await response.blob()).arrayBuffer();
    const asn1 = fromBER(rawOcspResponse);
    return new OCSPResponse({ schema: asn1.result });
}

async function getCRL(certificate: Certificate): Promise<CertificateRevocationList> {
    const crlExt = certificate.extensions.find(e => e.extnID === '2.5.29.31').parsedValue as CRLDistributionPoints;
    const crlUrl = crlExt.distributionPoints[0].distributionPoint[0].value as string;

    const response = await fetch(crlUrl, {
        mode: "cors",
        cache: "no-cache"
    });
    const crlString = await response.text();
    const crlAsn1 = parsePem(crlString);
    return new CertificateRevocationList({schema: crlAsn1.result});
}

function validateCertContent(cert: Certificate): ValidationResult {
    const subject: AttributeTypeAndValue[] = cert.subject.typesAndValues;
    const mcpMrn: string = subject.find(v => v.type as unknown === "0.9.2342.19200300.100.1.1").value.valueBlock.value; // UID
    const orgMcpMrn: string = subject.find(v => v.type as unknown === "2.5.4.10").value.valueBlock.value; // O
    if (!isValidMcpMRN(mcpMrn))
        return {valid: false, error: "Entity MRN is not a valid MCP MRN"};

    if (!isValidMcpMRN(orgMcpMrn))
        return {valid: false, error: "Organization MRN is not a valid MCP MRN"};

    const type: string = subject.find(v => v.type as unknown === "2.5.4.11").value.valueBlock.value; // OU
    if (!mcpTypes.includes(type))
        return {valid: false, error: "Entity type is not included in certificate"};

    const mrnSplit = mcpMrn.split(':');
    if (mrnSplit[3] !== type)
        return {valid: false, error: "Entity type is not included in MRN"};

    const orgMrnSplit = orgMcpMrn.split(":");
    if ((mrnSplit[4] !== orgMrnSplit[4]) || (mrnSplit[5] !== orgMrnSplit[5]))
        return {valid: false, error: "Information in entity MRN does not correspond with information in organization MRN"};

    const altNames = cert.extensions.find(e => e.extnID === "2.5.29.17").parsedValue.altNames;

    const mcpAttrDict: {[key: string]: McpAltNameAttribute} = {};
    altNames.forEach((gn: GeneralName) => {
        const oid = gn.value.valueBlock.value[0].valueBlock.value;
        const oidString = hexOidsToString(oid);
        const value = gn.value.blockName[""].valueBlock.value;
        mcpAttrDict[oidString] = {
            oid: oidString,
            value: value
        };
    });

    if (mcpAttrDict["2.25.323100633285601570573910217875371967771"] // Flagstate
        || mcpAttrDict["2.25.208070283325144527098121348946972755227"] // Callsign
        || mcpAttrDict["2.25.285632790821948647314354670918887798603"]) { // Port of register
        if (!["vessel", "service"].includes(type)) {
            return {valid: false, error: "Certificate contains fields that are only valid for vessels or services"};
        }
    }

    // IMO number
    if (mcpAttrDict["2.25.291283622413876360871493815653100799259"]) {
        if (!["vessel", "service"].includes(type)) {
            return {valid: false, error: "Only a vessel or service certificate can contain an IMO number"};
        }
        const imoNumber = mcpAttrDict["2.25.291283622413876360871493815653100799259"].value;
        if (!/^(IMO)?( )?\d{7}$/.test(imoNumber)) {
            return {valid: false, error: "The IMO number is not valid"};
        }
    }

    // MMSI number
    if (mcpAttrDict["2.25.328433707816814908768060331477217690907"]) {
        if (!["vessel", "service"].includes(type)) {
            return {valid: false, error: "Only a vessel or service certificate can contain an MMSI number"};
        }
        const mmsiNumber = mcpAttrDict["2.25.328433707816814908768060331477217690907"].value;
        if (!/^\d{9}$/.test(mmsiNumber)) {
            return {valid: false, error: "The MMSI number is not valid"};
        }
    }

    // AIS type
    if (mcpAttrDict["2.25.107857171638679641902842130101018412315"]) {
        if (!["vessel", "service"].includes(type)) {
            return {valid: false, error: "Only a vessel or service certificate can contain an AIS type"};
        }
        const aisType = mcpAttrDict["2.25.107857171638679641902842130101018412315"].value;
        if (!/^[AB]$/.test(aisType)) {
            return {valid: false, error: "The AIS type is not valid"};
        }
    }

    // Ship MRN
    if (mcpAttrDict["2.25.268095117363717005222833833642941669792"]) {
        if (type !== "service") {
            return {valid: false, error: "Only a service certificate can have a ship MRN"};
        }
        const shipMrn = mcpAttrDict["2.25.268095117363717005222833833642941669792"].value;
        if (!isValidMcpMRN(shipMrn)) {
            return {valid: false, error: "Ship MRN is not a valid MCP MRN"};
        }
    }

    // MRN
    if (mcpAttrDict["2.25.271477598449775373676560215839310464283"]) {
        if (!["vessel", "user", "device", "service", "mms"].includes(type)) {
            return {valid: false, error: `Certificates for type ${type} cannot contain the field 2.25.271477598449775373676560215839310464283`};
        }
        const mrn = mcpAttrDict["2.25.271477598449775373676560215839310464283"].value;
        if (!isValidMcpMRN(mrn) || mrn !== mcpMrn) {
            return {valid: false, error: "The field 2.25.271477598449775373676560215839310464283 is either not a valid MCP MRN or not equal to the UID"};
        }
    }

    // Subsidiary MRN
    if (mcpAttrDict["2.25.133833610339604538603087183843785923701"]) {
        if (!["vessel", "user", "device", "service", "mms"].includes(type)) {
            return {valid: false, error: `Certificates for type ${type} cannot contain a subsidiary MRN`};
        }
        const mrn = mcpAttrDict["2.25.133833610339604538603087183843785923701"].value;
        if (mrn === mcpMrn || !isValidMRN(mrn)) {
            return {valid: false, error: "Subsidiary MRN is either the same as primary MRN or not a valid MRN"};
        }
    }

    // Home MMS URL
    if (mcpAttrDict["2.25.171344478791913547554566856023141401757"]) {
        const url = mcpAttrDict["2.25.171344478791913547554566856023141401757"].value;
        if (!["vessel", "user", "device", "service", "mms"].includes(type)) {
            return {valid: false, error: `Certificates for type ${type} cannot contain a Home MMS URL`};
        }
        if (!isValidURL(url)) {
            return {valid: false, error: "Home MMS URL is not a valid URL"};
        }
    }

    // URL
    if (mcpAttrDict["2.25.245076023612240385163414144226581328607"]) {
        const url = mcpAttrDict["2.25.245076023612240385163414144226581328607"].value;
        if (type !== "mms") {
            return {valid: false, error: "Certificate cannot have a URL if it is not an MMS"};
        }
        if (!isValidURL(url)) {
            return {valid: false, error: "MMS URL is not valid"}
        }
    }

    let pubKeyInfo = cert.subjectPublicKeyInfo;

    if ((pubKeyInfo.algorithm.algorithmId !== "1.2.840.10045.2.1") || (((pubKeyInfo.parsedKey as ECPublicKey).namedCurve !== "1.3.132.0.34") && ((pubKeyInfo.parsedKey as ECPublicKey).namedCurve !== "1.2.840.10045.3.1.7")))
        return {valid: false, error: "The certificate is not using an MCC endorsed public key algorithm"};

    return {valid: true, error: ""};
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
    } catch (e) {
        return false;
    }
    return true;
}

function hexOidsToString(oids: Array<LocalSidValueBlock>): string {
    const oidStrings: Array<string> = new Array(oids.length);
    const firstByte = new Uint8Array(oids[0].valueHex)[0];
    oidStrings[0] = Math.floor(firstByte / 40).toString();
    oidStrings[1] = (firstByte % 40).toString();

    for (let i = 1; i < oids.length; i++) {
        const buf = new Uint8Array(oids[i].valueHex);

        let result = 0n;

        for (let j = (buf.length - 1); j >= 0; j--) {
            result += BigInt(buf[(buf.length - 1) - j] * Math.pow(2, 7 * j));
        }
        oidStrings.push(result.toString());
    }

    return oidStrings.join(".");
}
