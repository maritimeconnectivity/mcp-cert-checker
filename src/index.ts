import 'bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import {fromBER} from "asn1js";
import Certificate from "pkijs/src/Certificate";

const pemTextArea: HTMLTextAreaElement = document.getElementById('certTextArea') as HTMLTextAreaElement;
const certFileUploader: HTMLInputElement = document.getElementById('certFileUploader') as HTMLInputElement;

const subCaPemTextArea: HTMLTextAreaElement = document.getElementById('subCaCertTextArea') as HTMLTextAreaElement;
const subCaFileUploader: HTMLInputElement = document.getElementById('subCaCertFileUploader') as HTMLInputElement;

const caPemTextArea: HTMLTextAreaElement = document.getElementById('caCertTextArea') as HTMLTextAreaElement;
const caFileUploader: HTMLInputElement = document.getElementById('caCertFileUploader') as HTMLInputElement;

const submitButton: HTMLButtonElement = document.getElementById('submitBtn') as HTMLButtonElement;
const clearButton: HTMLButtonElement = document.getElementById('clearBtn') as HTMLButtonElement;

let cert: string;
let subCaCert: string | ArrayBuffer;
let caCert: string | ArrayBuffer;

pemTextArea.addEventListener("input", () => {
   cert = pemTextArea.value;
});

certFileUploader.addEventListener("input", async () => {
    if (certFileUploader.files.length > 0) {
        const file = certFileUploader.files[0];
        let content = await file.text();
        let matches = [...content.matchAll(/(-----BEGIN CERTIFICATE-----)(.*?)(-----END CERTIFICATE-----)/smg)];
        if (matches.length > 0) {
            cert = matches[0][0];
            pemTextArea.value = cert;
            if (matches.length > 1) {
                subCaCert = matches[1][0];
                subCaPemTextArea.value = subCaCert;
                if (matches.length > 2) {
                    caCert = matches[2][0];
                    caPemTextArea.value = caCert;
                }
            }
        } else {
            alert('Certificate must be PEM encoded!');
        }
    }
});

subCaPemTextArea.addEventListener("input", () => {
   subCaCert = subCaPemTextArea.value;
});

subCaFileUploader.addEventListener("input", async () => {
    if (subCaFileUploader.files.length > 0) {
        const file = subCaFileUploader.files[0];
        subCaCert = await file.arrayBuffer();
    }
});

caPemTextArea.addEventListener("input", () => {
   caCert = caPemTextArea.value;
});

caFileUploader.addEventListener("input", async () => {
   if (caFileUploader.files.length > 0) {
       const file = caFileUploader.files[0];
       caCert = await file.arrayBuffer();
   }
});

submitButton.addEventListener("click", () => {
   if (cert) {
       const b64 = cert.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
       const binary = atob(b64);
       const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
       //console.log(bytes);
       const asn1 = fromBER(bytes.buffer);
       const certificate = new Certificate({schema: asn1.result});
       //console.log(certificate);
   }
});

clearButton.addEventListener("click", () => {
   location.reload();
});
