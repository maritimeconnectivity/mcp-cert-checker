import 'bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';

const pemTextArea: HTMLTextAreaElement = document.getElementById('certTextArea') as HTMLTextAreaElement;
const certFileUploader: HTMLInputElement = document.getElementById('certFileUploader') as HTMLInputElement;

const subCaPemTextArea: HTMLTextAreaElement = document.getElementById('subCaCertTextArea') as HTMLTextAreaElement;
const subCaFileUploader: HTMLInputElement = document.getElementById('subCaCertFileUploader') as HTMLInputElement;

const caPemTextArea: HTMLTextAreaElement = document.getElementById('caCertTextArea') as HTMLTextAreaElement;
const caFileUploader: HTMLInputElement = document.getElementById('caCertFileUploader') as HTMLInputElement;

const submitButton: HTMLButtonElement = document.getElementById('submitBtn') as HTMLButtonElement;

let cert: string | ArrayBuffer;
let subCaCert: string | ArrayBuffer;
let caCert: string | ArrayBuffer;

pemTextArea.addEventListener("input", () => {
   cert = pemTextArea.value;
});

certFileUploader.addEventListener("input", async () => {
    if (certFileUploader.files.length > 0) {
        const file = certFileUploader.files[0];
        cert = await file.arrayBuffer();
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
       if (typeof cert === "string") {
           const b64 = cert.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
           const bytes = atob(b64);
       } else if (cert instanceof ArrayBuffer) {

       }
   }
});
