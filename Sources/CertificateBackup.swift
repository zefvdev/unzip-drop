//
//  CertificateBackup.swift
//  Encrypted backup and restore functionality.
//

import Foundation
import CryptoKit
import Compression
import UIKit

struct BackupEntry: Codable {
    let id: String
    let name: String
    let p12Data: Data
    let provisionData: Data
    let password: String
    let timestamp: Date
    let bundleVersion: String = "1.0"
}

struct BackupFile: Codable {
    let version: String = "1.0"
    let createdAt: Date
    let deviceName: String
    let entries: [BackupEntry]
    let checksumHash: String
}

@MainActor
final class BackupManager: ObservableObject {
    static let shared = BackupManager()
    @Published var backups: [BackupMetadata] = []
    @Published var lastBackupDate: Date? = nil
    @Published var lastError: String? = nil
    
    private let backupDir = AppPaths.dir("backups")
    private let encryptionKeyIdentifier = "com.unzipdrop.backup.key"
    private static let maxBackupSize = 500 * 1024 * 1024 // 500MB limit
    
    struct BackupMetadata: Identifiable, Codable {
        let id: String
        let deviceName: String
        let createdAt: Date
        let certificateCount: Int
        let fileSize: Int
        
        var sizeFormatted: String {
            let bytes = Double(fileSize)
            if bytes < 1024 {
                return String(format: "%.0f B", bytes)
            } else if bytes < 1024 * 1024 {
                return String(format: "%.2f KB", bytes / 1024)
            } else {
                return String(format: "%.2f MB", bytes / (1024 * 1024))
            }
        }
    }
    
    private init() {
        loadBackups()
    }
    
    /// Create encrypted backup of all certificates
    func createBackup(certificates: [Certificate]) async throws -> BackupMetadata {
        var entries: [BackupEntry] = []
        
        for cert in certificates {
            guard let p12Data = try? Data(contentsOf: cert.p12URL),
                  let provData = try? Data(contentsOf: cert.provisionURL),
                  let password = Keychain.get("cert-" + cert.id) else {
                continue
            }
            
            entries.append(BackupEntry(
                id: cert.id,
                name: cert.name,
                p12Data: p12Data,
                provisionData: provData,
                password: password,
                timestamp: cert.addedAt
            ))
        }
        
        guard !entries.isEmpty else {
            lastError = "No certificates to backup"
            throw BackupError.encryptionFailed
        }
        
        let backup = BackupFile(
            createdAt: Date(),
            deviceName: UIDevice.current.name,
            entries: entries,
            checksumHash: entries.map { $0.id }.joined().sha256Hash()
        )
        
        // Encode and compress
        let encoded = try JSONEncoder().encode(backup)
        let compressed = try compressData(encoded)
        
        // Check size limit
        guard compressed.count <= Self.maxBackupSize else {
            lastError = "Backup size exceeds 500MB limit"
            throw BackupError.compressionFailed
        }
        
        // Encrypt with device key
        let encrypted = try encryptData(compressed)
        
        // Save to file in background
        return try await saveBackupFile(encrypted: encrypted, backup: backup)
    }
    
    /// Restore certificates from backup
    func restoreBackup(metadata: BackupMetadata, store: CertificateStore) async throws -> Int {
        let fileName = "backup-\(metadata.id).uzd"
        let fileURL = backupDir.appendingPathComponent(fileName)
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            lastError = "Backup file not found"
            throw BackupError.backupNotFound
        }
        
        let encrypted = try Data(contentsOf: fileURL)
        let compressed = try decryptData(encrypted)
        let decompressed = try decompressData(compressed)
        let backup = try JSONDecoder().decode(BackupFile.self, from: decompressed)
        
        // Verify checksum
        let calculatedHash = backup.entries.map { $0.id }.joined().sha256Hash()
        guard calculatedHash == backup.checksumHash else {
            lastError = "Backup integrity check failed"
            throw BackupError.corruptedBackup
        }
        
        // Restore entries
        var restoredCount = 0
        var failedCerts: [String] = []
        
        for entry in backup.entries {
            do {
                _ = try store.importPair(
                    name: entry.name,
                    p12: entry.p12Data,
                    password: entry.password,
                    provision: entry.provisionData,
                    makeActive: restoredCount == 0
                )
                restoredCount += 1
            } catch {
                failedCerts.append(entry.name)
                ZLog.warn("Failed to restore certificate \(entry.name): \(error.localizedDescription)\n")
            }
        }
        
        if !failedCerts.isEmpty {
            lastError = "Restored \(restoredCount)/\(backup.entries.count) certificates. Failed: \(failedCerts.joined(separator: ", "))"
        } else {
            lastError = "Successfully restored \(restoredCount) certificates"
        }
        
        return restoredCount
    }
    
    /// Export backup to Files app
    func exportBackup(metadata: BackupMetadata, to destination: URL) async throws {
        let fileName = "backup-\(metadata.id).uzd"
        let fileURL = backupDir.appendingPathComponent(fileName)
        let timestamp = metadata.createdAt.formatted(date: .abbreviated, time: .omitted).replacingOccurrences(of: "/", with: "-")
        let exportName = "unzip-drop-backup-\(timestamp).uzd"
        let exportURL = destination.appendingPathComponent(exportName)
        
        try FileManager.default.copyItem(at: fileURL, to: exportURL)
        lastError = "Backup exported successfully"
    }
    
    /// Delete backup
    func deleteBackup(metadata: BackupMetadata) async throws {
        let fileName = "backup-\(metadata.id).uzd"
        let fileURL = backupDir.appendingPathComponent(fileName)
        try FileManager.default.removeItem(at: fileURL)
        backups.removeAll { $0.id == metadata.id }
        await MainActor.run { saveMetadata() }
    }
    
    // MARK: - Private Helpers
    
    private func getOrCreateEncryptionKey() throws -> SymmetricKey {
        // Try to retrieve key from Keychain
        if let keyData = Keychain.get(encryptionKeyIdentifier),
           let data = Data(base64Encoded: keyData) {
            return SymmetricKey(data: data)
        }
        
        // Generate new key and store in Keychain
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        Keychain.set(encryptionKeyIdentifier, keyData.base64EncodedString())
        return key
    }
    
    private func encryptData(_ data: Data) throws -> Data {
        do {
            let key = try getOrCreateEncryptionKey()
            let box = try AES.GCM.seal(data, using: key)
            guard let combined = box.combined else {
                lastError = "Encryption failed: could not combine cipher and nonce"
                throw BackupError.encryptionFailed
            }
            return combined
        } catch {
            lastError = "Encryption error: \(error.localizedDescription)"
            throw BackupError.encryptionFailed
        }
    }
    
    private func decryptData(_ data: Data) throws -> Data {
        do {
            let key = try getOrCreateEncryptionKey()
            let box = try AES.GCM.SealedBox(combined: data)
            return try AES.GCM.open(box, using: key)
        } catch {
            lastError = "Decryption error: \(error.localizedDescription)"
            throw BackupError.corruptedBackup
        }
    }
    
    private func compressData(_ data: Data) throws -> Data {
        var compressed = Data()
        let sourceCount = data.count
        let destinationCapacity = sourceCount + (sourceCount / 16) + 64 // Add extra buffer
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: destinationCapacity)
        defer { buffer.deallocate() }
        
        let compressedSize = data.withUnsafeBytes { sourceBuffer -> Int in
            guard let sourceBytes = sourceBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return 0
            }
            return compression_encode_buffer(
                buffer, destinationCapacity,
                sourceBytes, sourceCount,
                nil,
                COMPRESSION_ZLIB
            )
        }
        
        guard compressedSize > 0 else {
            lastError = "Compression failed or returned empty result"
            throw BackupError.compressionFailed
        }
        
        compressed = Data(bytes: buffer, count: compressedSize)
        return compressed
    }
    
    private func decompressData(_ data: Data) throws -> Data {
        // Start with 4x the compressed size
        var decompressed = Data(count: max(data.count * 4, 1024))
        
        let decompressedSize = decompressed.withUnsafeMutableBytes { destBuffer in
            data.withUnsafeBytes { srcBuffer -> Int in
                guard let destBytes = destBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let srcBytes = srcBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return 0
                }
                return compression_decode_buffer(
                    destBytes,
                    decompressed.count,
                    srcBytes,
                    data.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }
        
        guard decompressedSize > 0 else {
            lastError = "Decompression failed"
            throw BackupError.compressionFailed
        }
        
        decompressed.count = decompressedSize
        return decompressed
    }
    
    private func saveBackupFile(encrypted: Data, backup: BackupFile) async throws -> BackupMetadata {
        let backupID = UUID().uuidString
        let fileName = "backup-\(backupID).uzd"
        let fileURL = backupDir.appendingPathComponent(fileName)
        
        try encrypted.write(to: fileURL)
        
        let metadata = BackupMetadata(
            id: backupID,
            deviceName: backup.deviceName,
            createdAt: backup.createdAt,
            certificateCount: backup.entries.count,
            fileSize: encrypted.count
        )
        
        backups.append(metadata)
        lastBackupDate = Date()
        saveMetadata()
        lastError = "Backup created successfully"
        
        return metadata
    }
    
    private func loadBackups() {
        guard let data = try? Data(contentsOf: backupDir.appendingPathComponent(".metadata.json")),
              let metadata = try? JSONDecoder().decode([BackupMetadata].self, from: data) else {
            return
        }
        self.backups = metadata.sorted { $0.createdAt > $1.createdAt }
        self.lastBackupDate = backups.first?.createdAt
    }
    
    private func saveMetadata() {
        guard let encoded = try? JSONEncoder().encode(backups) else {
            lastError = "Failed to encode metadata"
            return
        }
        do {
            try encoded.write(to: backupDir.appendingPathComponent(".metadata.json"))
        } catch {
            lastError = "Failed to save metadata: \(error.localizedDescription)"
        }
    }
}

enum BackupError: LocalizedError {
    case backupNotFound
    case corruptedBackup
    case encryptionFailed
    case compressionFailed
    case invalidInput
    
    var errorDescription: String? {
        switch self {
        case .backupNotFound:
            return "Backup file not found."
        case .corruptedBackup:
            return "Backup file is corrupted or integrity check failed."
        case .encryptionFailed:
            return "Failed to encrypt backup."
        case .compressionFailed:
            return "Failed to compress or decompress backup."
        case .invalidInput:
            return "Invalid backup input."
        }
    }
}

extension String {
    func sha256Hash() -> String {
        let data = Data(self.utf8)
        let digest = Insecure.SHA1.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
