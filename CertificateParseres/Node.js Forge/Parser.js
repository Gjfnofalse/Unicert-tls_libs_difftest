const fs = require('fs');
const forge = require('node-forge');

function numberToTypeName(num) {
    if (num === 1){
        return "Rfc822Name"
    }else if (num === 2){
        return "DnsName"
    }else if (num === 6){
        return "URI"
    }else if (num === 7){
        return "IP"
    }else if (num === 8 ){
        return "regID"
    }else{
        return "unsupport SAN/IAN type."
    }
}

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
    let x509Cert
    let Subject
    let Issuer
    for (const item of jsonData) {
        let Cert = {
            sha1: item.sha1,
            Status: true,
            Err: [],
            FocusField:item.FocusField,
            FocusFieldValue:item.FocusFieldValue,
            InsertValue:item.InsertValue,
            description:item.description,
            Subject_e : true,
            Subject :{ //ref x509.js line:130_144
                CN : null,
                C : null,
                L : null,
                ST : null,
                O : null,
                OU : null,
                E : null
            },
            Issuer_e : true,
            Issuer :{
                CN : null,
                C : null,
                L : null,
                ST : null,
                O : null,
                OU : null,
                E : null
            },
            SAN : [],
            IAN : []
        };
        
        try {
            x509Cert = forge.pki.certificateFromPem(item.pem)
        } catch (error) {
            Cert.Status = false;
            Cert.Err.push(error.message);
            
            try{
                x509CertV3J = JSON.stringify(Cert) +'\n' 
                try {
                    fs.appendFileSync(outputFilePath, x509CertV3J, 'utf8');
                } catch (error) {
                    console.log(`sha1:${Cert.sha1},The parsing of the x509 object was successful, the JSON serialization was successful, but write to file:${outputFilePath}error:`,error.message)
                }
                continue
            }catch(error){
                console.log(`sha1:${Cert.sha1},The parsing of the x509 object was successful, but the JSON serialization failed,`,error.message)
                continue
            }
        }
        
        Subject = x509Cert.subject
        Issuer = x509Cert.issuer
        
        if (!(Object.keys(Subject).length === 0 && Subject.constructor === Object)){
            let Subject_c_arr = x509Cert.subject.getField('C')
            if(Subject_c_arr!=null){
                Cert.Subject.C = {
                    data : Subject_c_arr.value,
                    jstype : typeof Subject_c_arr.value
                }
            }
            
            let Subject_cn_arr = x509Cert.subject.getField('CN')
            if(Subject_cn_arr!=null){
                Cert.Subject.CN = {
                    data : Subject_cn_arr.value,
                    jstype : typeof Subject_cn_arr.value
                } 
            }

            let Subject_l_arr = x509Cert.subject.getField('L')
            if(Subject_l_arr!=null){
                Cert.Subject.L = {
                    data : Subject_l_arr.value,
                    jstype : typeof Subject_l_arr.value
                }
            }

            let Subject_st_arr = x509Cert.subject.getField('ST')
            if(Subject_st_arr!=null){
                Cert.Subject.ST = {
                    data : Subject_st_arr.value,
                    jstype : typeof Subject_st_arr.value
                }
            }

            let Subject_o_arr = x509Cert.subject.getField('O')
            if(Subject_o_arr!=null){
                Cert.Subject.O = {
                    data : Subject_o_arr.value,
                    jstype : typeof Subject_o_arr.value
                }
            }

            let Subject_ou_arr = x509Cert.subject.getField('OU')
            if(Subject_ou_arr!=null){
                Cert.Subject.OU = {
                    data : Subject_ou_arr.value,
                    jstype : typeof Subject_ou_arr.value
                }
            }

            let Subject_e_arr = x509Cert.subject.getField('E')
            if(Subject_e_arr!=null){
                Cert.Subject.E = {
                    data : Subject_e_arr.value,
                    jstype : typeof Subject_e_arr.value
                }
            }
        }else{
            Cert.Subject_e = false
        }
        if (!(Object.keys(Issuer).length === 0 && Issuer.constructor === Object)){
            let Issuer_c_arr = x509Cert.issuer.getField('C')
            if(Issuer_c_arr!=null){
                Cert.Issuer.C = {
                    data : Issuer_c_arr.value,
                    jstype : typeof Issuer_c_arr.value
                }
            }

            let Issuer_cn_arr = x509Cert.issuer.getField('CN')
            if(Issuer_cn_arr!=null){
                Cert.Issuer.CN = {
                    data : Issuer_cn_arr.value,
                    jstype : typeof Issuer_cn_arr.value
                } 
            }
            
            let Issuer_l_arr = x509Cert.issuer.getField('L')
            if(Issuer_l_arr!=null){
                Cert.Issuer.L = {
                    data : Issuer_l_arr.value,
                    jstype : typeof Issuer_l_arr.value
                }
            }

            let Issuer_st_arr = x509Cert.issuer.getField('ST')
            if(Issuer_st_arr!=null){
                Cert.Issuer.ST = {
                    data : Issuer_st_arr.value,
                    jstype : typeof Issuer_st_arr.value
                }
            }

            let Issuer_o_arr = x509Cert.issuer.getField('O')
            if(Issuer_o_arr!=null){
                Cert.Issuer.O = {
                    data : Issuer_o_arr.value,
                    jstype : typeof Issuer_o_arr.value
                }
            }

            let Issuer_ou_arr = x509Cert.issuer.getField('OU')
            if(Issuer_ou_arr!=null){
                Cert.Issuer.OU = {
                    data : Issuer_ou_arr.value,
                    jstype : typeof Issuer_ou_arr.value
                }
            }

            let Issuer_e_arr = x509Cert.issuer.getField('E')
            if(Issuer_e_arr!=null){
                Cert.Issuer.E = {
                    data : Issuer_e_arr.value,
                    jstype : typeof Issuer_e_arr.value
                }
            }
        }else{
            Cert.Issuer_e = false
        }
        
        let SAN = x509Cert.getExtension('subjectAltName')
        let IAN = x509Cert.getExtension('IssuerAltName')

        if(SAN!=null){
            let tv_SAN = SAN.altNames
            for (const v of tv_SAN) {
                let TypeString = numberToTypeName(v.type)
                let Value = v.value
                let item
                if (TypeString !='IP' && TypeString !='regID'){
                    item = {
                        [TypeString] : Value,
                        jstype : typeof Value
                    }
                }else if(TypeString ==='IP'){
                    item = {
                        [TypeString] : Value,
                        ip : v.ip,
                        jstype : typeof Value
                    }
                }else if(TypeString ==='regID'){
                    item = {
                        [TypeString] : Value,
                        oid : v.oid,
                        jstype : typeof Value
                    }
                }else{
                }
                Cert.SAN.push(item)
            }
        }

        if(IAN!=null){
            let tv_IAN = IAN.altNames
            for (const v of tv_IAN) {
                let TypeString = numberToTypeName(v.type)
                let Value = v.value
                let item
                if (TypeString !='IP' && TypeString !='regID'){
                    item = {
                        [TypeString] : Value,
                        jstype : typeof Value
                    }
                }else if(TypeString ==='IP'){
                    item = {
                        [TypeString] : Value,
                        ip : v.ip,
                        jstype : typeof Value
                    }
                }else if(TypeString ==='regID'){
                    item = {
                        [TypeString] : Value,
                        oid : v.oid,
                        jstype : typeof Value
                    }
                }else{
                }
                Cert.IAN.push(item)
            }
        }

        try{
            x509CertV3J = JSON.stringify(Cert) +'\n'
            try {
                fs.appendFileSync(outputFilePath, x509CertV3J, 'utf8');
            } catch (error) {
                console.log(`sha1:${Cert.sha1},The parsing of the x509 object was successful, the JSON serialization was successful, but write to file:${outputFilePath}error:`,error.message)
                continue;
            }
        }catch(error){
            console.log(`sha1:${Cert.sha1},The parsing of the x509 object was successful, the JSON serialization was failed,`,error.message)
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