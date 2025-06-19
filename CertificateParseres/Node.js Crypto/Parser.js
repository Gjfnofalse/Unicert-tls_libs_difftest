const fs = require('fs');
const { X509Certificate } = require('node:crypto');

function readJsonLinesFromFileSync(filePath) {
    const data = [];
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    
    for (let line of lines) {
        if (line.trim() !== '') {
            try {
                const json = JSON.parse(line);
                data.push(json);
            } catch (error) {
                console.error(`can not parse JSON line: ${line}. error: ${error.message}`);
            }
        }
    }
    
    return data;
}

function processCertsFromJsonFile(inputFilePath, outputFilePath) {
    const jsonData = readJsonLinesFromFileSync(inputFilePath);
    let x509CertV3J

    for (const item of jsonData) {
        let Cert = {
            sha1: item.sha1,
            Status: true,
            Err: [],
            FocusField:item.FocusField,
            FocusFieldValue:item.FocusFieldValue,
            InsertValue:item.InsertValue,
            description:item.description,
            Subject: null,
            Issuer: null,
            AIA: null,
            SAN: null
        };
        
        //parse X.509Certs
        try {
            const x509Cert = new X509Certificate(item.pem);
            Cert.Subject = x509Cert.subject;
            Cert.Issuer = x509Cert.issuer;
            Cert.AIA = {
                data:x509Cert.infoAccess,
                jstype : typeof x509Cert.infoAccess
            };
            x509Cert.Check
            Cert.SAN = {
                data : x509Cert.subjectAltName,
                jstype : typeof x509Cert.subjectAltName
            };
        } catch (error) {
            Cert.Status = false;
            Cert.Err.push(error.message);
        }

        try{
            x509CertV3J = JSON.stringify(Cert) +'\n' 
            try {
                fs.appendFileSync(outputFilePath, x509CertV3J, 'utf8');
            } catch (error) {
                console.log(`sha1:${Cert.sha1},The parsing of the x509 object was successful and the JSON serialization was successful,but write to file:${outputFilePath}failed:`,error.message)
                continue;
            }
        }catch(error){
            console.log(`sha1:${Cert.sha1},The parsing of the x509 object was successful but the JSON serialization was failed,`,error.message)
        }
    }
}

if (process.argv.length != 4) {
    console.error('Please provide the paths of the input file and the output file!');
    process.exit(1);
}

const inputFilePath = process.argv[2];
const outputFilePath = process.argv[3];

try {
    processCertsFromJsonFile(inputFilePath, outputFilePath);
} catch (error) {
    console.error(`Processing file failed: ${inputFilePath}. error: ${error.message}`);
    process.exit(1);
}