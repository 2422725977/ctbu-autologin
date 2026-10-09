// ocr_vision.swift —— macOS 内置 Vision 框架 OCR 命令行助手
// 编译: swiftc -O -o ocr_vision ocr_vision.swift
// 用法: ./ocr_vision <图片路径>
// 输出: 识别出的文字（失败时以 ERR: 开头并返回非零码）
//
// 用途：识别统一身份认证（CAS）的图片验证码。
// 注意它和 ePortal 的验证码不一样 —— CAS 的是 200x60 JPEG、带干扰线、
// 字形有扭曲，没法用模板逐像素匹配，只能真做 OCR。
import Foundation
import Vision
import AppKit

let args = CommandLine.arguments
guard args.count > 1 else {
    FileHandle.standardError.write("usage: ocr_vision <image>\n".data(using: .utf8)!)
    exit(2)
}

let path = args[1]
guard let image = NSImage(contentsOfFile: path),
      let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    print("ERR: cannot load image \(path)")
    exit(3)
}

let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = false
request.recognitionLanguages = ["en-US"]

let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
do {
    try handler.perform([request])
} catch {
    print("ERR: \(error.localizedDescription)")
    exit(4)
}

var pieces: [String] = []
for observation in (request.results ?? []) {
    if let candidate = observation.topCandidates(1).first {
        pieces.append(candidate.string)
    }
}
print(pieces.joined())
