import 'bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import Asn1js, {fromBER} from "asn1js";
import Certificate from "pkijs/src/Certificate";
import CertificateChainValidationEngine from "pkijs/src/CertificateChainValidationEngine";
import OCSPRequest from "pkijs/src/OCSPRequest";
import InfoAccess from "pkijs/src/InfoAccess";
import OCSPResponse from "pkijs/src/OCSPResponse";

const certFileUploader: HTMLInputElement = document.getElementById('certFileUploader') as HTMLInputElement;
const subCaFileUploader: HTMLInputElement = document.getElementById('subCaCertFileUploader') as HTMLInputElement;
const caFileUploader: HTMLInputElement = document.getElementById('caCertFileUploader') as HTMLInputElement;

const submitButton: HTMLButtonElement = document.getElementById('submitBtn') as HTMLButtonElement;
const checkOCSPButton: HTMLButtonElement = document.getElementById('ocspBtn') as HTMLButtonElement;
const clearButton: HTMLButtonElement = document.getElementById('clearBtn') as HTMLButtonElement;

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

submitButton.addEventListener("click", () => {
    const parsedCerts: Array<Certificate> = certs.map(c => parseCertificate(c));
    const validationEngine: CertificateChainValidationEngine = new CertificateChainValidationEngine(
        {
            certs: parsedCerts.slice(0, parsedCerts.length - 1),
            trustedCerts: [parsedCerts[parsedCerts.length - 1]]
        });
    validationEngine.verify().then(r => {
        if (r?.result) {
            alert("The trust chain was successfully verified!");
        } else {
            alert("The trust chain could not be verified!");
        }
    }, () => alert("This was bad!"));
});

checkOCSPButton.addEventListener("click", async () => {
    const parsedCerts: Array<Certificate> = certs.map(parseCertificate);
    const ocspReq: OCSPRequest = new OCSPRequest();

    await ocspReq.createForCertificate(parsedCerts[0], {hashAlgorithm: "SHA-384", issuerCertificate: parsedCerts[1]});
    const ocsp = ocspReq.toSchema(true) as Asn1js.Sequence;
    const tmp = parsedCerts[0].extensions.filter(e => e.extnID === "1.3.6.1.5.5.7.1.1")[0].parsedValue as InfoAccess;
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
    const ocspResponse = new OCSPResponse({schema: asn1.result});
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

clearButton.addEventListener("click", () => {
   location.reload();
});

function parseCertificate(pemCert: string): Certificate {
    const b64 = pemCert.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    const asn1 = fromBER(bytes.buffer);
    return new Certificate({schema: asn1.result});
}

function extractCerts(pemCerts: string): void {
    let matches = [...pemCerts.matchAll(/(-----BEGIN CERTIFICATE-----)(.*?)(-----END CERTIFICATE-----)/smg)];
    matches.forEach((m, i) => {
       certs[i] = m[0];
       textAreas[i].value = certs[i];
    });
}
