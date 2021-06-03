import 'bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';

const pemTextArea: HTMLTextAreaElement = document.getElementById('certTextArea') as HTMLTextAreaElement;
const certFileUploader: HTMLInputElement = document.getElementById('certFileUploader') as HTMLInputElement;

const subCaPemTextArea: HTMLTextAreaElement = document.getElementById('subCaCertTextArea') as HTMLTextAreaElement;
const subCaFileUploader: HTMLInputElement = document.getElementById('subCaCertFileUploader') as HTMLInputElement;

const caPemTextArea: HTMLTextAreaElement = document.getElementById('caCertTextArea') as HTMLTextAreaElement;
const caFileUploader: HTMLInputElement = document.getElementById('caCertFileUploader') as HTMLInputElement;

const submitButton: HTMLButtonElement = document.getElementById('submitBtn') as HTMLButtonElement;

let cert, subCaCert, caCert: string | ArrayBuffer;

pemTextArea.addEventListener("input", () => {
   cert = pemTextArea.value;
});

certFileUploader.addEventListener("input", async () => {
    if (certFileUploader.files.length > 0) {
        let file = certFileUploader.files[0];
        cert = await file.arrayBuffer();
    }
});

subCaPemTextArea.addEventListener("input", () => {
   subCaCert = subCaPemTextArea.value;
});

subCaFileUploader.addEventListener("input", async () => {
    if (subCaFileUploader.files.length > 0) {
        let file = subCaFileUploader.files[0];
        subCaCert = await file.arrayBuffer();
    }
});

caPemTextArea.addEventListener("input", () => {
   caCert = caPemTextArea.value;
});

caFileUploader.addEventListener("input", async () => {
   if (caFileUploader.files.length > 0) {
       let file = caFileUploader.files[0];
       caCert = await file.arrayBuffer();
   }
});
