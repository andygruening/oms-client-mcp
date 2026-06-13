import Foundation
import Security

let usage = "usage: keychain-helper.swift <get|set|delete> <service> <key>"
let notFoundExitCode: Int32 = 2

func fail(_ message: String, code: Int32 = 1) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(code)
}

func statusMessage(_ status: OSStatus) -> String {
  if let message = SecCopyErrorMessageString(status, nil) as String? {
    return message
  }

  return "Security.framework returned status \(status)"
}

func validateIdentifier(_ value: String, name: String) {
  if value.isEmpty {
    fail("\(name) must not be empty", code: 64)
  }

  if value.unicodeScalars.contains(where: { $0.value < 32 }) {
    fail("\(name) must not contain control characters", code: 64)
  }
}

func findGenericPassword(
  service: String,
  account: String,
  includePasswordData: Bool
) -> (status: OSStatus, item: SecKeychainItem?, passwordData: Data?) {
  var passwordLength: UInt32 = 0
  var passwordPointer: UnsafeMutableRawPointer?
  var item: SecKeychainItem?

  let status: OSStatus
  if includePasswordData {
    status = service.withCString { servicePointer in
      account.withCString { accountPointer in
        SecKeychainFindGenericPassword(
          nil,
          UInt32(strlen(servicePointer)),
          servicePointer,
          UInt32(strlen(accountPointer)),
          accountPointer,
          &passwordLength,
          &passwordPointer,
          &item
        )
      }
    }
  } else {
    status = service.withCString { servicePointer in
      account.withCString { accountPointer in
        SecKeychainFindGenericPassword(
          nil,
          UInt32(strlen(servicePointer)),
          servicePointer,
          UInt32(strlen(accountPointer)),
          accountPointer,
          nil,
          nil,
          &item
        )
      }
    }
  }

  var passwordData: Data?
  if status == errSecSuccess, includePasswordData, let passwordPointer {
    passwordData = Data(bytes: passwordPointer, count: Int(passwordLength))
    SecKeychainItemFreeContent(nil, passwordPointer)
  }

  return (status, item, passwordData)
}

func getPassword(service: String, account: String) {
  let result = findGenericPassword(
    service: service,
    account: account,
    includePasswordData: true
  )

  if result.status == errSecItemNotFound {
    fail("not found", code: notFoundExitCode)
  }

  guard result.status == errSecSuccess, let passwordData = result.passwordData else {
    fail(statusMessage(result.status))
  }

  FileHandle.standardOutput.write(passwordData)
}

func setPassword(service: String, account: String, passwordData: Data) {
  let result = findGenericPassword(
    service: service,
    account: account,
    includePasswordData: false
  )

  if result.status == errSecSuccess {
    guard let item = result.item else {
      fail("Keychain item lookup succeeded without returning an item")
    }
    let status = passwordData.withUnsafeBytes { bytes in
      SecKeychainItemModifyAttributesAndData(
        item,
        nil,
        UInt32(bytes.count),
        bytes.baseAddress!
      )
    }

    if status != errSecSuccess {
      fail(statusMessage(status))
    }

    return
  }

  if result.status != errSecItemNotFound {
    fail(statusMessage(result.status))
  }

  let status = service.withCString { servicePointer in
    account.withCString { accountPointer in
      passwordData.withUnsafeBytes { passwordPointer in
        SecKeychainAddGenericPassword(
          nil,
          UInt32(strlen(servicePointer)),
          servicePointer,
          UInt32(strlen(accountPointer)),
          accountPointer,
          UInt32(passwordPointer.count),
          passwordPointer.baseAddress!,
          nil
        )
      }
    }
  }

  if status != errSecSuccess {
    fail(statusMessage(status))
  }
}

func deletePassword(service: String, account: String) {
  let result = findGenericPassword(
    service: service,
    account: account,
    includePasswordData: false
  )

  if result.status == errSecItemNotFound {
    return
  }

  guard result.status == errSecSuccess, let item = result.item else {
    fail(statusMessage(result.status))
  }

  let status = SecKeychainItemDelete(item)
  if status != errSecSuccess && status != errSecItemNotFound {
    fail(statusMessage(status))
  }
}

let args = CommandLine.arguments
guard args.count == 4 else {
  fail(usage, code: 64)
}

let operation = args[1]
let service = args[2]
let key = args[3]

validateIdentifier(service, name: "service")
validateIdentifier(key, name: "key")

switch operation {
case "get":
  getPassword(service: service, account: key)
case "set":
  setPassword(
    service: service,
    account: key,
    passwordData: FileHandle.standardInput.readDataToEndOfFile()
  )
case "delete":
  deletePassword(service: service, account: key)
default:
  fail(usage, code: 64)
}
