//Created by Vinay Hosamane K N
// vinayhosamane07@gmail.com

import Foundation
import Security

///Keychian keys typecasted to String.
struct KeychainKeys {
    
    static let kSecAttrKeyTypeKey = kSecAttrKeyType as String
    static let kSecAttrKeyClassKey = kSecAttrKeyClass as String
    static let kSecAttrAccessibleKey = kSecAttrAccessible as String
    static let kSecAttrApplicationTagKey = kSecAttrApplicationTag as String
    static let kSecAttrLabelKey = kSecAttrLabel as String
    static let kSecAttrSynchronizableKey = kSecAttrSynchronizable as String
    static let kSecClassKey = kSecClass as String
    static let kSecMatchLimitKey = kSecMatchLimit as String
    static let kSecReturnDataKey = kSecReturnData as String
    static let kSecReturnRefKey = kSecReturnRef as String
    static let kSecValueDataKey = kSecValueData as String
    static let kSecValueRefKey = kSecValueRef as String
    
}

///Keychain Items labels used by query builder.
struct KeychainItemLabels {
    
    static let encryptionKey = "UsageTracking_Encryption_Key"
    /*If we are adding IVData to output sequence while encrypted. Then we have to maintatin the IVData as well in Keychain.
     Otherwise we will lose the state of the encryption. Which leads to corrupted data.*/
    static let ivDataKey = "UsageTracking_IVData_key"
    static let saltLabel = "UsageTracking_Private_Salt"
    
    //Get all the labels in this model. This is a aggregator used by Keychian to take action in group.
    static func getAllLabels() -> [String] {
        return [KeychainItemLabels.encryptionKey, KeychainItemLabels.ivDataKey, KeychainItemLabels.saltLabel]
    }
    
}

///Keychain Items tags, which are used by query builder.
struct KeychainItemTags {
    
    static let encryptionServiceTag = "com.sap.epm.fpa.UsageTracking.Encryption.Service"
    /*If we want additional security on encryption, then we can add random bytes to ouput sequence. WHich is IVData.
     It is not used in current implementation. Kept it for future needs.*/
    static let ivDataServiceTag = "com.sap.epm.fpa.UsageTracking.IvData.Service"
    static let saltServiceTag = "com.sap.epm.fpa.UsageTracking.Salt.Service"
    
    //Get all the tags in this model. This is a aggregator used by Keychian to take action in group.
    static func getAllTags() -> [String] {
        return [KeychainItemTags.encryptionServiceTag, KeychainItemTags.ivDataServiceTag, KeychainItemTags.saltServiceTag]
    }
    
}

///Enum to handle keychain exceptions and provides localized description for the known error.
enum KeychainError: Error, LocalizedError {
    
    case keychainOSError(status: OSStatus)
    case dataValidationError
    
    //localized description for the error code.
    var localizedDescription: String {
        switch self {
        case .keychainOSError(let status):
            return KeyChainManager.convertOSStatusError(status)
        case .dataValidationError:
            return "Value passed is either nil or not a valid data." //has to be locallized
        }
    }
    
}

///Keychain operations, helpful to decide what query has to be build. Used by query builder.
enum KeychainOperation {
    
    case add
    case read
    case update
    case remove
    
}

///Keychain services like add, read, update and remove.
protocol KeychainServicesProvidable {
    ///  A Keychain service to add elements into Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes to identify the key item.
    ///     - value: Data to be stored in Keychain.
    /// - Returns: throws KeychainError exception if anything goes wrong.
    func add(data value: String, with query: QueryDataType) throws
    
    ///  A Keychain service to read elements from Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes
    /// - Returns: optional String with the fetched results. Throws error if exception occurs.
    func read(with query: QueryDataType) throws -> String?
    
    ///   A Keychain service to update the existing elements in Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes to identify the key item.
    ///     - attributes: new data value to be updated.
    /// - Returns: throws KeychainError exception if anything goes wrong.
    func update(with query: QueryDataType, with attributes: QueryDataType) throws
    
    ///  A Keychain service to remove elements from Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes
    /// - Returns: throws KeychainError exception if anything goes wrong.
    func remove(with query: QueryDataType) throws
    
    ///  A Keychain service to remove all elements related to usage tracking from Keychain container.
    ///  - Parameters:
    ///     - allLabels: array of attribute labels.
    ///     - allTags: array of attribute tags.
    /// - Returns: Bool value which can be discardable.
    @discardableResult
    func clear(allLabels: [String], Tags allTags: [String]) -> Bool
}

///User defined service which builds the query to access keychain
protocol KeychainQueryBuildable {
    ///   A query builder to access elements in Keychain.
    /// - Parameters:
    ///     - tag: Application tag. It is one of KeychainItemTags.
    ///     - label: Attribute label to uniquely identify the item. It is one of KeychainItemLabels.
    ///     - operation: This is used to decide what query to build. It is one of KeychainOperation.
    /// - Returns: Query to access the Keychain, throws KeychainError exception if anything goes wrong.
    func buildQuery(withTag tag: String, Label label: String, Operation operation: KeychainOperation) throws -> QueryDataType
}

///Generic Keychain container datatype
typealias QueryDataType = [String: Any]
//protocols composition
typealias KeychainDependencies = KeychainQueryBuildable & KeychainServicesProvidable

final class UsageTrackingKeychainManager: KeychainDependencies {
    
    static let sharedInstance = UsageTrackingKeychainManager()
    
    ///   A query builder to access elements in Keychain.
    /// - Parameters:
    ///     - tag: Application tag. It is one of KeychainItemTags.
    ///     - label: Attribute label to uniquely identify the item. It is one of KeychainItemLabels.
    ///     - operation: This is used to decide what query to build. It is one of KeychainOperation.
    /// - Returns: Query to access the Keychain, throws KeychainError exception if anything goes wrong.
    func buildQuery(withTag tag: String, Label label: String, Operation operation: KeychainOperation) throws -> QueryDataType {
        
        guard let tag = tag.data(using: .utf8) else {
            throw KeychainError.dataValidationError
        }
        
        var query: QueryDataType = [:]
        
        switch operation {
        case .add:
            query = [
                KeychainKeys.kSecClassKey: kSecClassKey as String,
                KeychainKeys.kSecAttrAccessibleKey: kSecAttrAccessibleWhenUnlocked as String,
                KeychainKeys.kSecAttrApplicationTagKey: tag,
                KeychainKeys.kSecAttrSynchronizableKey: kCFBooleanFalse,
                KeychainKeys.kSecAttrLabelKey: label,
                KeychainKeys.kSecAttrKeyTypeKey: kSecAttrKeyTypeRSA,
                KeychainKeys.kSecAttrKeyClassKey: kSecAttrKeyClassPrivate
            ]
        case .read:
            query = [
                KeychainKeys.kSecClassKey: kSecClassKey as String,
                KeychainKeys.kSecAttrAccessibleKey: kSecAttrAccessibleWhenUnlocked as String,
                KeychainKeys.kSecAttrApplicationTagKey: tag,
                KeychainKeys.kSecAttrSynchronizableKey: kCFBooleanFalse,
                KeychainKeys.kSecAttrLabelKey: label,
                KeychainKeys.kSecReturnDataKey: kCFBooleanTrue,
            ]
        case .remove:
            query = [
                KeychainKeys.kSecClassKey: kSecClassKey as String,
                KeychainKeys.kSecAttrAccessibleKey: kSecAttrAccessibleWhenUnlocked as String,
                KeychainKeys.kSecAttrApplicationTagKey: tag,
                KeychainKeys.kSecAttrSynchronizableKey: kCFBooleanFalse,
                KeychainKeys.kSecAttrLabelKey: label,
                KeychainKeys.kSecAttrKeyTypeKey: kSecAttrKeyTypeRSA,
                KeychainKeys.kSecAttrKeyClassKey: kSecAttrKeyClassPrivate
            ]
        case .update:
            //Have to handle
            print("have to handle update query for keychain")
        }
        
        return query
    }
    
    ///  A Keychain service to add elements into Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes to identify the key item.
    ///     - value: Data to be stored in Keychain.
    /// - Returns: throws KeychainError exception if anything goes wrong.
    func add(data value: String, with query: QueryDataType) throws {
        
        //Encrypt the data
        guard let value = value.data(using: .utf8) else {
            throw KeychainError.dataValidationError
        }
        
        var keyQuery = query
        keyQuery[KeychainKeys.kSecValueDataKey] = value
        
        //To avoid duplicate adding of same key in Keychain, first delete key if exists and then add.
        do {
            try remove(with: query)
        } catch let error as KeychainError {
            print(error.localizedDescription)
        }
        
        let status: OSStatus = SecItemAdd(keyQuery as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            print(KeychainError.keychainOSError(status: status).localizedDescription)
            throw KeychainError.keychainOSError(status: status)
        }
        
        print("Data added to keychain with no errors.")
    }
    
    ///  A Keychain service to read elements from Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes
    /// - Returns: optional String with the fetched results. Throws error if exception occurs.
    func read(with query: QueryDataType) throws -> String? {
        
        var result: CFTypeRef?
        
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            print(KeychainError.keychainOSError(status: status).localizedDescription)
            throw KeychainError.keychainOSError(status: status)
        }
        
        //Check the result is of Data type
        guard let data = result as? Data else {
            throw KeychainError.dataValidationError
        }
        //Decrypt the data and convert it into String dataType.
        
        //Convert Data to String using encoding and return.
        return String(bytes: data, encoding: .utf8)
    }
    
    ///   A Keychain service to update the existing elements in Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes to identify the key item.
    ///     - attributes: new data value to be updated.
    /// - Returns: throws KeychainError exception if anything goes wrong.
    func update(with query: QueryDataType, with attributes: QueryDataType) throws {
        
    }
    
    ///  A Keychain service to remove elements from Keychain container.
    /// - Parameters:
    ///     - query: dictionary of attributes
    /// - Returns: throws KeychainError exception if anything goes wrong.
    func remove(with query: QueryDataType) throws {
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            print(KeychainError.keychainOSError(status: status).localizedDescription)
            throw KeychainError.keychainOSError(status: status)
        }
        
        print("Data removed from keychain with no errors.")
    }
    
    ///  A Keychain service to remove all elements related to usage tracking from Keychain container.
    ///  - Parameters:
    ///     - allLabels: array of attribute labels.
    ///     - allTags: array of attribute tags.
    /// - Returns: Bool value which can be discardable.
    @discardableResult
    func clear(allLabels: [String], Tags allTags: [String]) -> Bool {
        
        guard allTags.count == allLabels.count else {
            print(KeychainError.dataValidationError.localizedDescription)
            return false
        }
        
        for (index, tag) in allTags.enumerated() {
            do {
                let removeQuery = try buildQuery(withTag: tag,
                                                 Label: allLabels[index],
                                                 Operation: .remove)
                try remove(with: removeQuery)
            } catch let error {
                print(error.localizedDescription)
                return false
            }
        }
        print("All Items with Usage Tracking tags are removed from Keychain.")
        return true
    }
    
}

