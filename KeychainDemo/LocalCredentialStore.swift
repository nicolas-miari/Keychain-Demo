//
//  LocalCredentialStore.swift
//  KeychainDemo
//
//  Created by Nicolás Miari on 2019/06/21.
//  Copyright © 2019 Nicolás Miari. All rights reserved.
//

import Foundation
import Security

/**
 Provides keychain-based support for secure, local storage and retrieval of the
 user's password.
 */
class LocalCredentialStore {

    private static let serviceName: String = {
        guard let name = Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String else {
            return "Unknown App"
        }
        return name
    }()

    private static let accountName = "Login Password"

    /**
     Returns `true` if successfully deleted, or no password was stored to begin
     with; In case of anomalous result `false` is returned.
     */
    @discardableResult  static func deleteStoredPassword() -> Bool {
        let deleteQuery: NSDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: accountName,
            kSecReturnData: false
        ]
        let result = SecItemDelete(deleteQuery as CFDictionary)
        switch result {
        case errSecSuccess, errSecItemNotFound:
            return true

        default:
            return false
        }
    }

    /**
     If a password is already stored, it is silently overwritten.
     */
    static func storePassword(_ password: String, protectWithPasscode: Bool, completion: (() -> Void)? = nil, failure: ((Error) -> Void)? = nil) {
        // Encode payload:
        guard let dataToStore = password.data(using: .utf8) else {
            failure?(NSError(localizedDescription: ""))
            return
        }

        // DELETE any previous entry:
        self.deleteStoredPassword()

        // INSERT new value:
        let protection: CFTypeRef = protectWithPasscode ? kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly : kSecAttrAccessibleWhenUnlocked
        let flags: SecAccessControlCreateFlags = protectWithPasscode ? .userPresence : []

        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            protection,
            flags,
            nil) else {
                failure?(NSError(localizedDescription: ""))
                return
        }

        let insertQuery: NSDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccessControl: accessControl,
            kSecValueData: dataToStore,
            kSecUseAuthenticationUI: kSecUseAuthenticationUIAllow,
            kSecAttrService: serviceName, // These two values identify the entry;
            kSecAttrAccount: accountName  // together they become the primary key in the Database.
        ]
        let resultCode = SecItemAdd(insertQuery as CFDictionary, nil)

        guard resultCode == errSecSuccess else {
            failure?(NSError(localizedDescription: ""))
            return
        }
        completion?()
    }

    /**
     If a password is stored and can be retrieved successfully, it is passed back as the argument of
     `completion`; otherwise, `nil` is passed.
     - note: Completion handler is always executed on themain thread.
     */
    static func loadPassword(completion: @escaping ((String?) -> Void)) {

        // [1] Perform search on background thread:
        DispatchQueue.global().async {
            let selectQuery: NSDictionary = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: serviceName,
                kSecAttrAccount: accountName,
                kSecReturnData: true,
                kSecUseOperationPrompt: "パスワードを引き出すのに、生体認証してください"
            ]
            var extractedData: CFTypeRef?
            let result = SecItemCopyMatching(selectQuery, &extractedData)

            // [2] Rendez-vous with the caller on the main thread:
            DispatchQueue.main.async {
                switch result {
                case errSecSuccess:
                    guard let data = extractedData as? Data, let password = String(data: data, encoding: .utf8) else {
                        return completion(nil)
                    }
                    completion(password)

                case errSecUserCanceled:
                    completion(nil)

                case errSecAuthFailed:
                    completion(nil)

                case errSecItemNotFound:
                    completion(nil)

                default:
                    completion(nil)
                }
            }
        }
    }
}

extension NSError {
    convenience init(localizedDescription: String) {
        self.init(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: localizedDescription])
    }
}

