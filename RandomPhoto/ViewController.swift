import UIKit
import Security
import LocalAuthentication
import CommonCrypto

func sha256(data: Data) -> Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}

class ViewController: UIViewController {
    
    let inputTextField = UITextField()
    let encryptButton = UIButton()
    let outputLabel = UILabel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    func setupUI() {
        // Input TextField setup
        inputTextField.placeholder = "Enter a random number"
        inputTextField.borderStyle = .roundedRect
        inputTextField.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(inputTextField)
        
        // Encrypt Button setup
        encryptButton.setTitle("Encrypt", for: .normal)
        encryptButton.backgroundColor = .blue
        encryptButton.translatesAutoresizingMaskIntoConstraints = false
        encryptButton.addTarget(self, action: #selector(encryptAction), for: .touchUpInside)
        view.addSubview(encryptButton)
        
        // Output Label setup
        outputLabel.text = "Encrypted output will appear here"
        outputLabel.numberOfLines = 0
        outputLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(outputLabel)
        
        NSLayoutConstraint.activate([
            inputTextField.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            inputTextField.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            inputTextField.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.8),
            
            encryptButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            encryptButton.topAnchor.constraint(equalTo: inputTextField.bottomAnchor, constant: 20),
            
            outputLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            outputLabel.topAnchor.constraint(equalTo: encryptButton.bottomAnchor, constant: 20),
            outputLabel.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.8)
        ])
    }
    
    @objc func encryptAction() {
        guard let randomNumber = inputTextField.text, !randomNumber.isEmpty,
              let dataToSign = randomNumber.data(using: .utf8),
              let privateKey = generatePrivateKey() else {
            outputLabel.text = "Error: Could not generate private key or sign data."
            return
        }
        
        
        if let signature = signData(privateKey: privateKey, data: dataToSign) {
            outputLabel.text = "Signature: \(signature.base64EncodedString())"
        } else {
            outputLabel.text = "Error: Could not sign data."
        }
        
        // Attempt to extract the key to demonstrate it's secured in the Secure Enclave

    //    attemptSecureEnclaveKeyExtraction(tag: "com.example.keys.mykey")

    }
    
    func deleteExistingKey(tag: String) {
        guard let tagData = tag.data(using: .utf8) else {
            print("Failed to create tag data")
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]

        // Attempt to delete the existing key
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            print("Old key deleted or not found.")
        } else {
            print("Failed to delete old key. Status code: \(status)")
        }
    }
    
    
    func generatePrivateKey() -> SecKey? {
        let tagString = "com.example.keys.mykey"
        // Ensure there are no existing keys with the same tag
        deleteExistingKey(tag: tagString)
        // 1. Create Keys Access Control
        guard let accessControl =
            SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet],
                nil)
        else {
            fatalError("cannot set access control")
        }
        
        
        // 2. Create Key Attributes
        guard let tag = "com.example.keys.mykey".data(using: .utf8) else {
            fatalError("cannot set tag")
        }
        let attributes: [String: Any] = [
             kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
             kSecAttrKeySizeInBits as String: 256,
             kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
             kSecPrivateKeyAttrs as String: [
                 kSecAttrIsPermanent as String: true,
                 kSecAttrApplicationTag as String: tag,
                 kSecAttrAccessControl as String: accessControl
             ]
         ]
         
        
        // 3. Generate Key Pairs
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error = error?.takeRetainedValue() {
                        print("Error creating a key: \(error)")
                    }
            return nil
        }

        return privateKey
    }
    
    func signData(privateKey: SecKey, data: Data) -> Data? {
        let digest = sha256(data: data)

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey,
                                                    .ecdsaSignatureMessageX962SHA256,
                                                    digest as CFData,
                                                    &error) as Data? else {
            print(error!.takeRetainedValue() as Error)
            return nil
        }
        
        return signature
    }
    

    
    
    }




