import 'bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import Asn1js, {fromBER, LocalBaseBlock} from "asn1js";
import Certificate from "pkijs/src/Certificate";
import CertificateChainValidationEngine from "pkijs/src/CertificateChainValidationEngine";
import OCSPRequest from "pkijs/src/OCSPRequest";
import InfoAccess from "pkijs/src/InfoAccess";
import OCSPResponse from "pkijs/src/OCSPResponse";
import CRLDistributionPoints from "pkijs/src/CRLDistributionPoints";
import CertificateRevocationList from "pkijs/src/CertificateRevocationList";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";

interface Asn1Struct {
    offset: number,
    result: LocalBaseBlock
}

const mcpMrnRegex: RegExp = /urn:mrn:mcp:(device|org|user|vessel|service|mms):([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|\/)*)/g;
const mcpTypes: Array<string> = ["device", "org", "user", "vessel", "service", "mms"];

const certFileUploader: HTMLInputElement = document.getElementById('certFileUploader') as HTMLInputElement;
const subCaFileUploader: HTMLInputElement = document.getElementById('subCaCertFileUploader') as HTMLInputElement;
const caFileUploader: HTMLInputElement = document.getElementById('caCertFileUploader') as HTMLInputElement;

const submitButton: HTMLButtonElement = document.getElementById('submitBtn') as HTMLButtonElement;
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
    const parsedCerts: Array<Certificate> = certs.map(c => parseCertificate(c));
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
    const cert = parsedCerts[0];
    console.log(cert);
    if (validateCertContent(cert))
        console.log("Good!");
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
    console.log(parsedCerts);

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
    const tmp = certificate.extensions.filter(e => e.extnID === "1.3.6.1.5.5.7.1.1")[0].parsedValue as InfoAccess;
    const ocspUrl = tmp.accessDescriptions[0].accessLocation.value;
    const response = await fetch(ocspUrl, {
        method: 'POST',
        mode: "cors",
        cache: "no-cache",
        headers: {
            'Content-Type': 'application/ocsp-request'
        },
        body: ocsp.toBER()
    });
    const rawOcspResponse = await (await response.blob()).arrayBuffer();
    const asn1 = fromBER(rawOcspResponse);
    return new OCSPResponse({ schema: asn1.result });
}

async function getCRL(certificate: Certificate): Promise<CertificateRevocationList> {
    const crlExt = certificate.extensions.filter(e => e.extnID === '2.5.29.31')[0].parsedValue as CRLDistributionPoints;
    const crlUrl = crlExt.distributionPoints[0].distributionPoint[0].value as string;

    const response = await fetch(crlUrl, {
        mode: "cors",
        cache: "no-cache"
    });
    const crlString = await response.text();
    const crlAsn1 = parsePem(crlString);
    return new CertificateRevocationList({schema: crlAsn1.result});
}

function validateCertContent(cert: Certificate): boolean {
    const subject: AttributeTypeAndValue[] = cert.subject.typesAndValues;
    const mcpMrn: string = subject.filter(v => v.type as unknown === "2.5.4.10")[0].value.valueBlock.value;
    if (!validateMcpMrnSyntax(mcpMrn))
        return false;
    console.log(mcpMrn);

    const type: string = subject.filter(v => v.type as unknown === "2.5.4.11")[0].value.valueBlock.value;
    if (!mcpTypes.includes(type))
        return false;



    return true;
}

function validateMcpMrnSyntax(mrn: string): boolean {
    return mcpMrnRegex.test(mrn);
}
