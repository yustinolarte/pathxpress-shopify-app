import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const serverPath = path.join(__dirname, 'server.js');
const logoPath = path.join(__dirname, 'logo_base64.txt');

try {
    let serverContent = fs.readFileSync(serverPath, 'utf8');

    // Read base64 content and remove newlines if any
    let logoBase64 = fs.readFileSync(logoPath, 'utf8').replace(/[\r\n]/g, '');

    const targetString = '<img src="https://pathxpress.net/pathxpress-logo.png" alt="PATHXPRESS" class="logo-img" />';
    const replacementString = `<img src="data:image/png;base64,${logoBase64}" alt="PATHXPRESS" class="logo-img" />`;

    if (serverContent.includes(targetString)) {
        serverContent = serverContent.replace(targetString, replacementString);
        fs.writeFileSync(serverPath, serverContent, 'utf8');
        console.log('Successfully replaced logo with base64 content.');
    } else {
        console.error('Target string not found in server.js');
        // Debugging: print a small chunk around where we expect it
        const index = serverContent.indexOf('class="logo-img"');
        if (index !== -1) {
            console.log('Found "logo-img" at index ' + index);
            console.log('Context:', serverContent.substring(index - 100, index + 50));
        }
    }

} catch (err) {
    console.error('Error updating logo:', err);
}
