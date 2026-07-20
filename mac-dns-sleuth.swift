//
//  mac-dns-sleuth.swift
//  Mac DNS Sleuth
//
//  DNS validation and troubleshooting utility
//
//  Provides DNS lookups and email authentication
//  validation using a bundled helper process based
//  on the checkdmarc project.
//
//  Features:
//
//      • SPF validation
//      • DMARC validation
//      • BIMI validation
//      • DNSSEC checks
//      • MX inspection
//      • MTA-STS validation
//      • Proofpoint verification
//      • Nameserver inspection
//      • SOA inspection
//      • WHOIS lookup
//      • Custom DNS queries
//
//  Configuration file:
//
//      ~/Library/Application Support/
//          Mac DNS Sleuth/
//              mac-dns-sleuth.conf
//
//  Log file:
//
//      ~/Library/Logs/
//          mac-dns-sleuth.log
//
//  Helper process:
//
//      mac-dns-sleuth-helper.bin
//
//  Helper requests and responses are exchanged
//  using JSON over standard input and output.
//
//  Default DNS providers:
//
//      System Default
//      Cloudflare
//      Google
//      Quad9
//
//  Documentation:
//
//      help.md
//      glossary.md
//
//  Resources:
//
//      header-logo.png
//      about-logo.png
//
//  Licensed under the BSD 3-Clause License.
//
//  Built with Swift, SwiftUI, Python, and
//  checkdmarc.
//
// Copyright (c) 2026 John Wood
// https://github.com/john-at-charpa/mac-dns-sleuth
//

import Cocoa
import SwiftUI

// MARK: - Models

struct DefaultChecks: Codable {
    var dnssec = false
    var spf = true
    var dmarc = true
    var bimi = true
    var mx = true
    var mtaSts = true
    var smtpTls = false
    var soa = true
    var nameserver = true
    var proofpoint = true
    var whois = true
}

struct AppConfig: Codable {
    var debug = false

    var defaultChecks = DefaultChecks()

    var dnsServers = [
        "System Default": "",
        "Cloudflare": "1.1.1.1,1.0.0.1",
        "Google": "8.8.8.8,8.8.4.4",
        "Quad9": "9.9.9.9,149.112.112.112",
    ]
}

// MARK: - Markdown Support

enum MarkdownLine {
    case h1(String)
    case h2(String)
    case h3(String)
    case bullet(String)
    case url(String)
    case text(String)
    case code(String)
    case bold(String)
    case rule
    case blank
}

func renderInlineMarkdown(
    _ text: String
) -> Text {
    if let attributed =
        try? AttributedString(
            markdown: text
        )
    {
        return Text(attributed)
    }

    return Text(text)
}

func parseMarkdown(
    _ markdown: String
) -> [MarkdownLine] {
    markdown
        .components(separatedBy: .newlines)
        .map { line in

            let line = line.trimmingCharacters(
                in: .whitespaces
            )

            if line.isEmpty {
                return .blank
            }

            if line == "---" {
                return .rule
            }

            if line.hasPrefix("`")
                && line.hasSuffix("`")
            {
                return .code(
                    String(
                        line.dropFirst().dropLast()
                    )
                )
            }

            if line.hasPrefix("# ") {
                return .h1(
                    String(line.dropFirst(2))
                )
            }

            if line.hasPrefix("## ") {
                return .h2(
                    String(line.dropFirst(3))
                )
            }

            if line.hasPrefix("### ") {
                return .h3(
                    String(line.dropFirst(4))
                )
            }

            if line.hasPrefix("- ") {
                return .bullet(
                    String(line.dropFirst(2))
                )
            }

            if line.hasPrefix("**")
                && line.hasSuffix("**")
            {
                return .bold(
                    String(
                        line.dropFirst(2)
                            .dropLast(2)
                    )
                )
            }

            if line.hasPrefix("http://")
                || line.hasPrefix("https://")
            {
                return .url(line)
            }

            return .text(line)
        }
}

// MARK: - Documentation Views

struct MarkdownDocumentView: View {
    let markdown: String

    var body: some View {
        let lines =
            parseMarkdown(markdown)

        ScrollView {
            VStack(
                alignment: .leading,
                spacing: 6
            ) {
                ForEach(
                    Array(lines.enumerated()),
                    id: \.offset
                ) { _, line in

                    switch line {
                    case let .h1(text):

                        Text(text)
                            .font(.largeTitle)
                            .bold()
                            .padding(.top, 8)
                            .padding(.bottom, 4)

                    case let .h2(text):

                        Text(text)
                            .font(.title2)
                            .bold()
                            .padding(.top, 10)
                            .padding(.bottom, 2)

                    case let .h3(text):

                        Text(text)
                            .font(.headline)
                            .padding(.top, 6)

                    case let .bullet(text):

                        HStack(
                            alignment: .top,
                            spacing: 8
                        ) {
                            Text("•")
                            renderInlineMarkdown(text)
                        }

                    case let .code(text):

                        Text(text)
                            .font(
                                .system(
                                    .body,
                                    design: .monospaced
                                )
                            )
                            .padding(8)
                            .background(
                                Color.blue.opacity(0.08)
                            )

                    case let .bold(text):

                        Text(text)
                            .bold()

                    case let .url(url):

                        if let link =
                            URL(string: url)
                        {
                            Link(url, destination: link)
                                .font(.callout)
                        }

                    case let .text(text):

                        renderInlineMarkdown(text)

                    case .rule:

                        Divider()
                            .padding(.vertical, 8)

                    case .blank:

                        Spacer()
                            .frame(height: 4)
                    }
                }
            }
            .textSelection(.enabled)
            .frame(
                maxWidth: .infinity,
                alignment: .leading
            )
            .padding(24)
        }
    }
}

struct HelpView: View {
    var body: some View {
        MarkdownDocumentView(
            markdown:
            bundledMarkdown("help")
        )
    }
}

struct GlossaryView: View {
    var body: some View {
        MarkdownDocumentView(
            markdown:
            bundledMarkdown("glossary")
        )
    }
}

struct AboutView: View {
    var appVersion: String {
        Bundle.main.object(
            forInfoDictionaryKey:
            "CFBundleShortVersionString"
        ) as? String ?? "Unknown"
    }

    var buildNumber: String {
        Bundle.main.object(
            forInfoDictionaryKey:
            "CFBundleVersion"
        ) as? String ?? "Unknown"
    }

    var body: some View {
        VStack(spacing: 12) {
            if let image =
                bundleImage("about-logo")
            {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.none)
                    .scaledToFit()
                    .frame(
                        width: 110,
                        height: 110
                    )
            }

            VStack(spacing: 4) {
                Text(
                    "Version \(appVersion) (\(buildNumber))"
                )

                Text(
                    "Built with Swift, Python, and checkdmarc"
                )

                Text(
                    "Licensed under the BSD 3-Clause License"
                )
                .foregroundStyle(.secondary)

                Text("© John Wood")
            }
            .font(.subheadline)

            Button("OK") {
                NSApp.keyWindow?.close()
            }
            .frame(width: 120)
        }
        .padding(20)
        .frame(
            minWidth: 300,
            minHeight: 250
        )
    }
}

// MARK: - Configuration

enum ConfigManager {
    static let configDir =
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(
                "Library/Application Support/Mac DNS Sleuth"
            )

    static let configFile =
        configDir.appendingPathComponent(
            "mac-dns-sleuth.conf"
        )

    static func load() -> AppConfig {
        let fm = FileManager.default

        if !fm.fileExists(
            atPath: configDir.path
        ) {
            try? fm.createDirectory(
                at: configDir,
                withIntermediateDirectories: true
            )
        }

        if !fm.fileExists(
            atPath: configFile.path
        ) {
            let config = AppConfig()

            save(config)

            return config
        }

        do {
            let data =
                try Data(contentsOf: configFile)

            return try JSONDecoder().decode(
                AppConfig.self,
                from: data
            )

        } catch {
            print(
                "Config load failed: \(error)"
            )

            return AppConfig()
        }
    }

    static func save(
        _ config: AppConfig
    ) {
        do {
            let encoder = JSONEncoder()

            encoder.outputFormatting = [
                .prettyPrinted,
                .sortedKeys,
            ]

            let data =
                try encoder.encode(config)

            try data.write(
                to: configFile
            )

        } catch {
            print(
                "Config save failed: \(error)"
            )
        }
    }
}

// MARK: - Application

class AppDelegate:
    NSObject,
    NSApplicationDelegate,
    NSWindowDelegate
{
    var window: NSWindow!
    var aboutWindow: NSWindow?
    var helpWindow: NSWindow?
    var glossaryWindow: NSWindow?

    var config = AppConfig()

    let logFile =
        FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent(
                "Library/Logs/mac-dns-sleuth.log"
            )

    var helperProcess: Process?
    var helperInput: Pipe?
    var helperOutput: Pipe?

    // MARK: - Window Management

    func windowShouldClose(
        _ sender: NSWindow
    ) -> Bool {
        sender.orderOut(nil)

        return false
    }

    func applicationShouldHandleReopen(_: NSApplication,
                                       hasVisibleWindows flag: Bool) -> Bool
    {
        if !flag {
            window.orderFrontRegardless()

            NSApp.activate(
                ignoringOtherApps: true
            )
        }

        return true
    }

    // MARK: - Menu Actions

    @objc
    func showAbout() {
        if aboutWindow == nil {
            aboutWindow = NSWindow(
                contentRect: NSRect(
                    x: 0,
                    y: 0,
                    width: 520,
                    height: 420
                ),
                styleMask: [
                    .titled,
                    .closable,
                ],
                backing: .buffered,
                defer: false
            )

            aboutWindow?.isReleasedWhenClosed = false

            aboutWindow?.title =
                "About Mac DNS Sleuth"

            aboutWindow?.contentView =
                NSHostingView(
                    rootView: AboutView()
                )
        }

        aboutWindow?.center()
        aboutWindow?.makeKeyAndOrderFront(nil)

        NSApp.activate(
            ignoringOtherApps: true
        )
    }

    @objc
    func showHelp() {
        if helpWindow == nil {
            helpWindow = NSWindow(
                contentRect: NSRect(
                    x: 0,
                    y: 0,
                    width: 700,
                    height: 700
                ),
                styleMask: [
                    .titled,
                    .closable,
                    .miniaturizable,
                    .resizable,
                ],
                backing: .buffered,
                defer: false
            )

            helpWindow?.isReleasedWhenClosed = false
            helpWindow?.title = "Mac DNS Sleuth Help"

            helpWindow?.contentView =
                NSHostingView(
                    rootView: HelpView()
                )
        }

        helpWindow?.center()
        helpWindow?.makeKeyAndOrderFront(nil)

        NSApp.activate(
            ignoringOtherApps: true
        )
    }

    func showError(
        _ message: String
    ) {
        DispatchQueue.main.async {
            let alert = NSAlert()

            alert.alertStyle = .critical

            alert.messageText =
                "Mac DNS Sleuth Error"

            alert.informativeText =
                message

            alert.addButton(
                withTitle: "OK"
            )

            alert.runModal()
        }
    }

    @objc
    func showGlossary() {
        if glossaryWindow == nil {
            glossaryWindow = NSWindow(
                contentRect: NSRect(
                    x: 0,
                    y: 0,
                    width: 700,
                    height: 700
                ),
                styleMask: [
                    .titled,
                    .closable,
                    .miniaturizable,
                    .resizable,
                ],
                backing: .buffered,
                defer: false
            )

            glossaryWindow?.isReleasedWhenClosed = false

            glossaryWindow?.title =
                "DNS Glossary"

            glossaryWindow?.contentView =
                NSHostingView(
                    rootView: GlossaryView()
                )
        }

        glossaryWindow?.center()
        glossaryWindow?.makeKeyAndOrderFront(nil)

        NSApp.activate(
            ignoringOtherApps: true
        )
    }

    @objc
    func openConfigFile() {
        let textEdit =
            URL(
                fileURLWithPath:
                "/System/Applications/TextEdit.app"
            )

        NSWorkspace.shared.open(
            [ConfigManager.configFile],
            withApplicationAt: textEdit,
            configuration: NSWorkspace.OpenConfiguration()
        )
    }

    @objc
    func openLogFile() {
        if !FileManager.default.fileExists(
            atPath: logFile.path
        ) {
            try? "".write(
                to: logFile,
                atomically: true,
                encoding: .utf8
            )
        }

        NSWorkspace.shared.open(logFile)
    }

    // MARK: - Logging

    func rotateLogIfNeeded() {
        guard
            FileManager.default.fileExists(
                atPath: logFile.path
            )
        else {
            return
        }

        guard
            let attrs =
            try? FileManager.default
                .attributesOfItem(
                    atPath: logFile.path
                ),
                let size =
                attrs[.size] as? NSNumber
        else {
            return
        }

        let maxSize = 5_000_000

        if size.intValue > maxSize {
            try? FileManager.default.removeItem(
                at: logFile
            )
        }
    }

    func debug(
        _ message: String
    ) {
        guard config.debug else {
            return
        }

        let line =
            "\(Date()) \(message)\n"

        guard let data =
            line.data(using: .utf8)
        else {
            return
        }

        rotateLogIfNeeded()

        if FileManager.default.fileExists(
            atPath: logFile.path
        ) {
            if let handle =
                try? FileHandle(
                    forWritingTo: logFile
                )
            {
                handle.seekToEndOfFile()

                handle.write(data)

                try? handle.close()
            }

        } else {
            try? data.write(
                to: logFile
            )
        }
    }

    // MARK: - Helper Process

    func helperURL() -> URL? {
        Bundle.main.url(
            forResource: "mac-dns-sleuth-helper",
            withExtension: "bin"
        )
    }

    func startHelper() {
        debug("startHelper called")
        let process = Process()

        let input = Pipe()
        let output = Pipe()

        process.standardInput = input
        process.standardOutput = output

        guard let helper = helperURL() else {
            let message =
                """
                Unable to locate:

                mac-dns-sleuth-helper.bin

                Ensure the helper exists in the
                application Resources folder.
                """

            debug(message)

            showError(message)

            return
        }

        process.executableURL = helper

        process.arguments = [
            "--daemon",
        ]

        do {
            try process.run()
            debug("Helper PID: \(process.processIdentifier)")

            helperProcess = process
            helperInput = input
            helperOutput = output

            debug("Helper started")

        } catch {
            debug("Helper failed: \(error)")
        }
    }

    func sendRequest(
        _ request: [String: Any]
    ) -> String {
        debug("REQUEST: \(request)")

        guard
            let delegate =
            NSApp.delegate as? AppDelegate,
            let process =
            delegate.helperProcess,
            process.isRunning,
            let helperInput =
            delegate.helperInput,
            let helperOutput =
            delegate.helperOutput
        else {
            let message = """
            Unable to communicate with the
            Mac DNS Sleuth helper.

            Please restart Mac DNS Sleuth.
            """

            debug(message)

            showError(message)

            return ""
        }
        do {
            let data =
                try JSONSerialization.data(
                    withJSONObject: request
                )

            var json =
                String(
                    data: data,
                    encoding: .utf8
                )!

            json += "\n"

            helperInput.fileHandleForWriting.write(
                json.data(using: .utf8)!
            )

            let response =
                helperOutput
                    .fileHandleForReading
                    .availableData

            let result =
                String(
                    data: response,
                    encoding: .utf8
                ) ?? """
                {
                    "error": "Unable to decode response"
                }
                """

            debug("RESPONSE: \(result)")

            return result

        } catch {
            debug("ERROR: \(error)")

            return """
            {
                "error": "\(error)"
            }
            """
        }
    }

    // MARK: - NSApplicationDelegate

    func applicationDidFinishLaunching(
        _: Notification
    ) {
        config = ConfigManager.load()

        debug("Config loaded")
        debug("applicationDidFinishLaunching")

        startHelper()

        let mainMenu = NSMenu()

        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)

        let appMenu = NSMenu()
        appMenuItem.submenu = appMenu

        appMenu.addItem(
            withTitle: "About Mac DNS Sleuth",
            action: #selector(showAbout),
            keyEquivalent: ""
        )

        appMenu.addItem(NSMenuItem.separator())

        appMenu.addItem(
            withTitle: "Open Config File",
            action: #selector(openConfigFile),
            keyEquivalent: ""
        )

        appMenu.addItem(
            withTitle: "Open Log File",
            action: #selector(openLogFile),
            keyEquivalent: ""
        )

        appMenu.addItem(NSMenuItem.separator())

        appMenu.addItem(
            withTitle: "Quit Mac DNS Sleuth",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )

        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)

        let editMenu = NSMenu(title: "Edit")
        editMenuItem.submenu = editMenu

        editMenu.addItem(
            withTitle: "Copy",
            action: #selector(NSText.copy(_:)),
            keyEquivalent: "c"
        )

        editMenu.addItem(
            withTitle: "Paste",
            action: #selector(NSText.paste(_:)),
            keyEquivalent: "v"
        )

        editMenu.addItem(
            withTitle: "Select All",
            action: #selector(NSText.selectAll(_:)),
            keyEquivalent: "a"
        )

        let helpMenu = NSMenu(title: "Help")

        let helpMenuItem = NSMenuItem()
        helpMenuItem.submenu = helpMenu
        mainMenu.addItem(helpMenuItem)

        helpMenu.addItem(
            withTitle: "Mac DNS Sleuth Help",
            action: #selector(showHelp),
            keyEquivalent: ""
        )

        helpMenu.addItem(
            withTitle: "DNS Glossary",
            action: #selector(showGlossary),
            keyEquivalent: ""
        )

        NSApp.mainMenu = mainMenu
        NSApp.helpMenu = helpMenu

        window = NSWindow(
            contentRect: NSRect(
                x: 0,
                y: 0,
                width: 800,
                height: 700
            ),
            styleMask: [
                .titled,
                .closable,
                .miniaturizable,
                .resizable,
            ],
            backing: .buffered,
            defer: false
        )

        window.delegate = self

        window.title = "Mac DNS Sleuth"

        window.contentView = NSHostingView(
            rootView: ContentView()
        )

        window.center()
        window.makeKeyAndOrderFront(nil)
        window.minSize = NSSize(
            width: 900,
            height: 650
        )
    }

    func applicationWillTerminate(
        _: Notification
    ) {
        debug("Stopping helper")

        helperProcess?.terminate()
    }
}

// MARK: - Result Sections

struct SPFSection: View {
    let spf: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("SPF")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let record =
                        spf["record"] as? String
                    {
                        copyAction(record)
                    }
                }
            }

            if let record =
                spf["record"] as? String
            {
                Text(record)
                    .font(
                        .system(
                            .body,
                            design: .monospaced
                        )
                    )
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
                    .frame(
                        maxWidth: .infinity,
                        alignment: .leading
                    )
                    .padding(8)
                    .background(
                        Color.blue.opacity(0.10)
                    )
            }

            if let valid =
                spf["valid"] as? Bool
            {
                Text(
                    "Status: \(valid ? "Valid" : "Invalid")"
                )
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct DMARCSection: View {
    let dmarc: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("DMARC")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let record =
                        dmarc["record"] as? String
                    {
                        copyAction(record)
                    }
                }
            }

            if let record =
                dmarc["record"] as? String
            {
                Text(record)
                    .font(
                        .system(
                            .body,
                            design: .monospaced
                        )
                    )
                    .textSelection(.enabled)
                    .frame(
                        maxWidth: .infinity,
                        alignment: .leading
                    )
                    .padding(8)
                    .background(
                        Color.blue.opacity(0.08)
                    )
            }

            if let valid =
                dmarc["valid"] as? Bool
            {
                Text(
                    "Status: \(valid ? "Valid" : "Invalid")"
                )
            }

            if let tags =
                dmarc["tags"] as? [String: Any],
                let p =
                tags["p"] as? [String: Any],
                let policy =
                p["value"] as? String
            {
                Text("Policy: \(policy)")
            }

            if let warnings =
                dmarc["warnings"] as? [String],
                !warnings.isEmpty
            {
                Text("Warnings:")
                    .bold()

                ForEach(
                    warnings,
                    id: \.self
                ) { warning in

                    Text("• \(warning)")
                        .font(.caption)
                }
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct DNSSECSection: View {
    let dnssec: Bool

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("DNSSEC")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    copyAction(
                        dnssec
                            ? "DNSSEC Enabled"
                            : "DNSSEC Disabled"
                    )
                }
            }

            Text(
                dnssec
                    ? "Enabled"
                    : "Disabled"
            )
            .font(
                .system(
                    .body,
                    design: .monospaced
                )
            )
            .frame(
                maxWidth: .infinity,
                alignment: .leading
            )
            .padding(8)
            .background(
                Color.blue.opacity(0.10)
            )
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct NameserverSection: View {
    let nameserver: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("Nameservers")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let hostnames =
                        nameserver["hostnames"]
                            as? [String]
                    {
                        copyAction(
                            hostnames.joined(
                                separator: "\n"
                            )
                        )
                    }
                }
            }

            if let hostnames =
                nameserver["hostnames"]
                    as? [String]
            {
                Text(
                    hostnames.joined(
                        separator: "\n"
                    )
                )
                .font(
                    .system(
                        .body,
                        design: .monospaced
                    )
                )
                .textSelection(.enabled)
                .frame(
                    maxWidth: .infinity,
                    alignment: .leading
                )
                .padding(8)
                .background(
                    Color.blue.opacity(0.10)
                )
            }

            if let warnings =
                nameserver["warnings"]
                    as? [String],
                    !warnings.isEmpty
            {
                Text("Warnings:")
                    .bold()

                ForEach(
                    warnings,
                    id: \.self
                ) { warning in

                    Text("• \(warning)")
                        .font(.caption)
                }
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct SOASection: View {
    let soa: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("SOA")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let record =
                        soa["record"] as? String
                    {
                        copyAction(record)
                    }
                }
            }

            if let values =
                soa["values"] as? [String: Any]
            {
                if let primary =
                    values["primary_nameserver"] as? String
                {
                    Text("Primary Nameserver: \(primary)")
                }

                if let email =
                    values["rname_email_address"] as? String
                {
                    Text("Responsible: \(email)")
                }

                if let serial =
                    values["serial"] as? Int
                {
                    Text("Serial: \(serial)")
                }

                if let refresh =
                    values["refresh"] as? Int
                {
                    Text("Refresh: \(refresh)")
                }

                if let retry =
                    values["retry"] as? Int
                {
                    Text("Retry: \(retry)")
                }

                if let expire =
                    values["expire"] as? Int
                {
                    Text("Expire: \(expire)")
                }

                if let minimum =
                    values["minimum"] as? Int
                {
                    Text("Minimum TTL: \(minimum)")
                }
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct WHOISSection: View {
    let whois: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("WHOIS")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let raw =
                        whois["raw"] as? String
                    {
                        copyAction(raw)
                    }
                }
            }

            DisclosureGroup(
                "Show WHOIS Record"
            ) {
                if let raw =
                    whois["raw"] as? String
                {
                    Text(raw)
                        .font(
                            .system(
                                .body,
                                design: .monospaced
                            )
                        )
                        .textSelection(.enabled)
                        .frame(
                            maxWidth: .infinity,
                            alignment: .leading
                        )
                        .padding(8)
                        .background(
                            Color.blue.opacity(0.10)
                        )
                }
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct ProofpointSection: View {
    let proofpoint: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("Proofpoint Verification")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let records =
                        proofpoint["records"]
                            as? [String]
                    {
                        copyAction(
                            records.joined(
                                separator: "\n"
                            )
                        )

                    } else if let error =
                        proofpoint["error"]
                            as? String
                    {
                        copyAction(error)
                    }
                }
            }

            if let valid =
                proofpoint["valid"] as? Bool
            {
                Text(
                    valid
                        ? "Status: Present"
                        : "Status: Not Found"
                )
            }

            if let records =
                proofpoint["records"]
                    as? [String],
                    !records.isEmpty
            {
                Text(
                    records.joined(
                        separator: "\n"
                    )
                )
                .font(
                    .system(
                        .body,
                        design: .monospaced
                    )
                )
                .textSelection(.enabled)
                .frame(
                    maxWidth: .infinity,
                    alignment: .leading
                )
                .padding(8)
                .background(
                    Color.blue.opacity(0.10)
                )
            }

            if let error =
                proofpoint["error"] as? String
            {
                Text(error)
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct QuerySection: View {
    let query: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("Custom Query")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let results =
                        query["results"]
                            as? [String]
                    {
                        copyAction(
                            results.joined(
                                separator: "\n"
                            )
                        )
                    }
                }
            }

            if let name =
                query["name"] as? String
            {
                Text("Name: \(name)")
            }

            if let type =
                query["type"] as? String
            {
                Text("Type: \(type)")
            }

            if let results =
                query["results"] as? [String]
            {
                Text(
                    results.joined(
                        separator: "\n"
                    )
                )
                .font(
                    .system(
                        .body,
                        design: .monospaced
                    )
                )
                .textSelection(.enabled)
                .frame(
                    maxWidth: .infinity,
                    alignment: .leading
                )
                .padding(8)
                .background(
                    Color.blue.opacity(0.10)
                )
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct MTASTSSection: View {
    let mtaSts: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("MTA-STS")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    copyAction(
                        String(describing: mtaSts)
                    )
                }
            }

            if let valid =
                mtaSts["valid"] as? Bool
            {
                Text(
                    "Status: \(valid ? "Valid" : "Invalid")"
                )
            }

            if let error =
                mtaSts["error"] as? String
            {
                Text(error)
                    .font(
                        .system(
                            .body,
                            design: .monospaced
                        )
                    )
                    .frame(
                        maxWidth: .infinity,
                        alignment: .leading
                    )
                    .padding(8)
                    .background(
                        Color.blue.opacity(0.10)
                    )
            }

            if let id =
                mtaSts["id"] as? String
            {
                Text("ID: \(id)")
            }

            if let policy =
                mtaSts["policy"] as? [String: Any]
            {
                if let mode =
                    policy["mode"] as? String
                {
                    Text("Mode: \(mode)")
                }

                if let maxAge =
                    policy["max_age"] as? Int
                {
                    Text("Max Age: \(maxAge)")
                }

                if let hosts =
                    policy["mx"] as? [String]
                {
                    Text("MX Hosts:")
                        .bold()

                    Text(
                        hosts.joined(
                            separator: "\n"
                        )
                    )
                    .font(
                        .system(
                            .body,
                            design: .monospaced
                        )
                    )
                    .textSelection(.enabled)
                }
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct BIMISection: View {
    let bimi: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("BIMI")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let record =
                        bimi["record"] as? String
                    {
                        copyAction(record)

                    } else if let error =
                        bimi["error"] as? String
                    {
                        copyAction(error)
                    }
                }
            }

            if let valid =
                bimi["valid"] as? Bool
            {
                Text(
                    valid
                        ? "Status: Valid"
                        : "Status: Not Configured"
                )
            }

            if let selector =
                bimi["selector"] as? String
            {
                Text("Selector: \(selector)")
            }

            if let record =
                bimi["record"] as? String
            {
                Text(record)
                    .font(
                        .system(
                            .body,
                            design: .monospaced
                        )
                    )
                    .textSelection(.enabled)
                    .frame(
                        maxWidth: .infinity,
                        alignment: .leading
                    )
                    .padding(8)
                    .background(
                        Color.blue.opacity(0.10)
                    )
            }

            if let tags =
                bimi["tags"] as? [String: Any],
                let logo =
                tags["l"] as? [String: Any],
                let url =
                logo["value"] as? String
            {
                Text("Logo:")
                    .bold()

                Text(url)
                    .textSelection(.enabled)
            }

            if let error =
                bimi["error"] as? String
            {
                Text(error)
            }

            if let warnings =
                bimi["warnings"] as? [String],
                !warnings.isEmpty
            {
                Text("Warnings:")
                    .bold()

                ForEach(
                    warnings,
                    id: \.self
                ) { warning in

                    Text("• \(warning)")
                        .font(.caption)
                }
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

struct MXSection: View {
    let mx: [String: Any]

    let copyAction: (String) -> Void

    var body: some View {
        VStack(
            alignment: .leading,
            spacing: 8
        ) {
            HStack {
                Text("MX")
                    .font(.headline)

                Spacer()

                Button("Copy") {
                    if let hosts =
                        mx["hosts"]
                    {
                        copyAction(
                            String(
                                describing: hosts
                            )
                        )
                    }
                }
            }

            if let hosts =
                mx["hosts"] as? [[String: Any]]
            {
                ForEach(
                    Array(hosts.enumerated()),
                    id: \.offset
                ) { _, host in

                    if let preference =
                        host["preference"] as? Int,
                        let hostname =
                        host["hostname"] as? String
                    {
                        Text(
                            "\(preference) \(hostname)"
                        )
                        .font(
                            .system(
                                .body,
                                design: .monospaced
                            )
                        )
                        .frame(
                            maxWidth: .infinity,
                            alignment: .leading
                        )
                        .padding(8)
                        .background(
                            Color.blue.opacity(0.10)
                        )
                        .textSelection(.enabled)
                    }

                    if let addresses =
                        host["addresses"] as? [String],
                        !addresses.isEmpty
                    {
                        Text(
                            "Addresses: \(addresses.joined(separator: ", "))"
                        )
                    }

                    if let dnssec =
                        host["dnssec"] as? Bool
                    {
                        Text(
                            "DNSSEC: \(dnssec ? "Enabled" : "Disabled")"
                        )
                    }

                    if let tlsa =
                        host["tlsa"] as? [String],
                        !tlsa.isEmpty
                    {
                        Text("TLSA:")
                            .bold()

                        ForEach(
                            tlsa,
                            id: \.self
                        ) { record in

                            Text(record)
                                .font(
                                    .system(
                                        .caption,
                                        design: .monospaced
                                    )
                                )
                                .textSelection(.enabled)
                        }
                    }
                }
            }

            if let warnings =
                mx["warnings"] as? [String],
                !warnings.isEmpty
            {
                Text("Warnings:")
                    .bold()

                ForEach(
                    warnings,
                    id: \.self
                ) { warning in

                    Text("• \(warning)")
                        .font(.caption)
                }
            }
        }
        .padding(.vertical, 16)

        Divider()
    }
}

// MARK: - Main UI

struct ContentView: View {
    @State private var domain = ""

    @State private var dnssec: Bool
    @State private var spf: Bool
    @State private var dmarc: Bool
    @State private var bimi: Bool
    @State private var mx: Bool
    @State private var mtaSts: Bool
    @State private var smtpTls: Bool
    @State private var soa: Bool
    @State private var nameserver: Bool
    @State private var proofpoint: Bool
    @State private var whois: Bool

    @State private var queryName = ""
    @State private var queryType = "TXT"

    @State private var dnsServer = "System Default"

    @State private var isRunning = false

    @State private var output = """
    Ready.
    """

    init() {
        let checks =
            (NSApp.delegate as? AppDelegate)?
                .config.defaultChecks
                ?? DefaultChecks()

        _dnssec = State(initialValue: checks.dnssec)
        _spf = State(initialValue: checks.spf)
        _dmarc = State(initialValue: checks.dmarc)
        _bimi = State(initialValue: checks.bimi)
        _mx = State(initialValue: checks.mx)
        _mtaSts = State(initialValue: checks.mtaSts)
        _smtpTls = State(initialValue: checks.smtpTls)
        _soa = State(initialValue: checks.soa)
        _nameserver = State(initialValue: checks.nameserver)
        _proofpoint = State(initialValue: checks.proofpoint)
        _whois = State(initialValue: checks.whois)
    }

    var servers: [String] {
        let config =
            (NSApp.delegate as? AppDelegate)?
                .config

        return config?
            .dnsServers
            .keys
            .sorted() ?? []
    }

    let queryTypes = [
        "TXT",
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "PTR",
        "SRV",
        "CAA",
        "TLSA",
    ]

    var body: some View {
        ZStack {
            Color.gray.opacity(0.08)

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top, spacing: 24) {
                        VStack {
                            if let image =
                                bundleImage("header-logo")
                            {
                                Image(nsImage: image)
                                    .resizable()
                                    .interpolation(.none)
                                    .scaledToFit()
                            }

                            Spacer(minLength: 0)
                        }
                        .frame(width: 220)

                        VStack(alignment: .leading, spacing: 12) {
                            domainSection

                            dnsServerSection

                            checksSection

                            Divider()

                            customQuerySection

                            Divider()

                            buttonsSection
                        }
                    }

                    Rectangle()
                        .fill(Color.secondary.opacity(0.25))
                        .frame(height: 2)

                    structuredResults

                    resultsSection
                }
                .padding()
            }
        }
    }

    // MARK: - Sections

    var domainSection: some View {
        HStack {
            Text("Domain:")

            TextField(
                "icloud.com",
                text: $domain
            )
            .onSubmit {
                runLookup()
            }

            Button("Check") {
                runLookup()
            }
            if isRunning {
                ProgressView()
            }
        }
    }

    var dnsServerSection: some View {
        HStack(spacing: 2) {
            Text("DNS Server:")
            Picker("", selection: $dnsServer) {
                ForEach(servers, id: \.self) {
                    Text($0)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
        }
    }

    var checksSection: some View {
        VStack(alignment: .leading) {
            HStack {
                Toggle("BIMI", isOn: $bimi)
                Toggle("DMARC", isOn: $dmarc)
                Toggle("DNSSEC", isOn: $dnssec)
                Toggle("MTA-STS", isOn: $mtaSts)
            }

            HStack {
                Toggle("MX", isOn: $mx)
                Toggle("Nameserver", isOn: $nameserver)
                Toggle("Proofpoint Verification", isOn: $proofpoint)
            }

            HStack {
                Toggle("SOA", isOn: $soa)
                Toggle("SPF", isOn: $spf)
                Toggle("SMTP TLS", isOn: $smtpTls)
                Toggle("WHOIS", isOn: $whois)
            }
        }
    }

    var customQuerySection: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Custom Query:")
                    .frame(width: 100, alignment: .leading)

                TextField(
                    "_smtp._tls.example.com",
                    text: $queryName
                )
            }

            HStack {
                Text("Type")

                ComboBox(
                    selection: $queryType,
                    options: queryTypes
                )
                .frame(width: 150)

                Button("Run Custom Query") {
                    runCustomQuery()
                }
            }
        }
    }

    var buttonsSection: some View {
        HStack {
            Button("Copy All") {
                copy(output)
            }

            Button("Clear") {
                output = ""
            }

            Button("Save TXT") {
                saveResults()
            }

            Spacer()
        }
    }

    var structuredResults: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let json = parsedJSON() {
                if let spf =
                    json["spf"] as? [String: Any]
                {
                    SPFSection(
                        spf: spf,
                        copyAction: copy
                    )
                }

                if let dmarc =
                    json["dmarc"] as? [String: Any]
                {
                    DMARCSection(
                        dmarc: dmarc,
                        copyAction: copy
                    )
                }

                if let mx =
                    json["mx"] as? [String: Any]
                {
                    MXSection(
                        mx: mx,
                        copyAction: copy
                    )
                }

                if let dnssec =
                    json["dnssec"] as? Bool
                {
                    DNSSECSection(
                        dnssec: dnssec,
                        copyAction: copy
                    )
                }

                if let nameserver =
                    json["nameserver"] as? [String: Any]
                {
                    NameserverSection(
                        nameserver: nameserver,
                        copyAction: copy
                    )
                }

                if let soa =
                    json["soa"] as? [String: Any]
                {
                    SOASection(
                        soa: soa,
                        copyAction: copy
                    )
                }

                if let mtaSts =
                    json["mta_sts"] as? [String: Any]
                {
                    MTASTSSection(
                        mtaSts: mtaSts,
                        copyAction: copy
                    )
                }

                if let bimi =
                    json["bimi"] as? [String: Any]
                {
                    BIMISection(
                        bimi: bimi,
                        copyAction: copy
                    )
                }

                if let whois =
                    json["whois"] as? [String: Any]
                {
                    WHOISSection(
                        whois: whois,
                        copyAction: copy
                    )
                }

                if let proofpoint =
                    json["proofpoint"] as? [String: Any]
                {
                    ProofpointSection(
                        proofpoint: proofpoint,
                        copyAction: copy
                    )
                }

                if let query =
                    json["query"] as? [String: Any]
                {
                    QuerySection(
                        query: query,
                        copyAction: copy
                    )
                }
            }
        }
    }

    var resultsSection: some View {
        OutputTextView(text: $output)
    }

    // MARK: - Helpers

    func parsedJSON() -> [String: Any]? {
        guard let data = output.data(using: .utf8) else {
            return nil
        }

        return try? JSONSerialization.jsonObject(
            with: data
        ) as? [String: Any]
    }

    // MARK: - Actions

    func runCustomQuery() {
        guard !queryName.isEmpty else {
            return
        }

        isRunning = true
        output = ""

        DispatchQueue.global(
            qos: .userInitiated
        ).async {
            var request: [String: Any] = [
                "query_name": queryName,
                "query_type": queryType,
            ]

            if let config =
                (NSApp.delegate as? AppDelegate)?.config,
                let servers =
                config.dnsServers[dnsServer],
                !servers.isEmpty
            {
                request["nameservers"] =
                    servers
                        .split(separator: ",")
                        .map {
                            $0.trimmingCharacters(
                                in: .whitespaces
                            )
                        }
            }

            let result =
                (NSApp.delegate as! AppDelegate)
                    .sendRequest(request)

            DispatchQueue.main.async {
                output = result
                isRunning = false
            }
        }
    }

    func runLookup() {
        let hasCustomQuery =
            !queryName.isEmpty &&
            !queryType.isEmpty

        guard !domain.isEmpty || hasCustomQuery else {
            return
        }

        guard
            dnssec ||
            spf ||
            dmarc ||
            bimi ||
            mx ||
            mtaSts ||
            smtpTls ||
            soa ||
            nameserver ||
            proofpoint ||
            whois ||
            hasCustomQuery
        else {
            output = "No checks selected."
            return
        }

        isRunning = true
        output = ""

        var request: [String: Any] = [
            "dnssec": dnssec,
            "spf": spf,
            "dmarc": dmarc,
            "bimi": bimi,
            "mx": mx,
            "mta_sts": mtaSts,
            "smtp_tls": smtpTls,
            "soa": soa,
            "nameserver": nameserver,
            "proofpoint": proofpoint,
            "whois": whois,
        ]

        if !domain.isEmpty {
            request["domain"] = domain
        }

        if let config =
            (NSApp.delegate as? AppDelegate)?.config,
            let servers =
            config.dnsServers[dnsServer],
            !servers.isEmpty
        {
            request["nameservers"] =
                servers
                    .split(separator: ",")
                    .map {
                        $0.trimmingCharacters(
                            in: .whitespaces
                        )
                    }
        }
        if hasCustomQuery {
            request["query_name"] = queryName
            request["query_type"] = queryType
        }

        DispatchQueue.global(
            qos: .userInitiated
        ).async {
            let result =
                (NSApp.delegate as! AppDelegate)
                    .sendRequest(request)

            DispatchQueue.main.async {
                output = result
                isRunning = false
            }
        }
    }

    func copy(
        _ text: String
    ) { NSPasteboard.general.clearContents()

        NSPasteboard.general.setString(
            text,
            forType: .string
        )
    }

    func saveResults() { let panel = NSSavePanel()

        panel.allowedContentTypes = [.plainText]

        panel.nameFieldStringValue =
            "dns-results.txt"

        panel.begin { result in

            guard result == .OK,
                  let url = panel.url
            else {
                return
            }

            try? output.write(
                to: url,
                atomically: true,
                encoding: .utf8
            )
        }
    }
}

// MARK: - Custom Controls

struct ComboBox: NSViewRepresentable {
    @Binding var selection: String

    let options: [String]

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeNSView(
        context: Context
    ) -> NSComboBox {
        let comboBox = NSComboBox()

        comboBox.delegate =
            context.coordinator

        comboBox.addItems(
            withObjectValues: options
        )

        comboBox.stringValue =
            selection

        return comboBox
    }

    func updateNSView(
        _ comboBox: NSComboBox,
        context _: Context
    ) {
        comboBox.stringValue = selection
    }

    class Coordinator:
        NSObject,
        NSComboBoxDelegate
    {
        var parent: ComboBox

        init(
            _ parent: ComboBox
        ) {
            self.parent = parent
        }

        func controlTextDidChange(
            _ notification: Notification
        ) { if let comboBox =
            notification.object
                as? NSComboBox
            {
                parent.selection =
                    comboBox.stringValue
            }
        }

        func comboBoxSelectionDidChange(
            _ notification: Notification
        ) { if let comboBox =
            notification.object as? NSComboBox {
                parent.selection =
                    comboBox.objectValueOfSelectedItem
                        as? String ?? ""
            }
        }
    }
}

struct OutputTextView: NSViewRepresentable {
    @Binding var text: String
    func makeNSView(
        context _: Context
    ) -> NSScrollView {
        let textView = NSTextView()

        textView.isEditable = false
        textView.isSelectable = true

        textView.font = NSFont.monospacedSystemFont(
            ofSize: 12,
            weight: .regular
        )

        let scrollView = NSScrollView()

        scrollView.hasVerticalScroller = true
        scrollView.documentView = textView

        return scrollView
    }

    func updateNSView(
        _ scrollView: NSScrollView,
        context _: Context
    ) {
        if let textView =
            scrollView.documentView as? NSTextView
        {
            textView.string = text
        }
    }
}

// MARK: - Resource Helpers

func bundledMarkdown(
    _ name: String
) -> String {
    guard let url =
        Bundle.main.url(
            forResource: name,
            withExtension: "md"
        )
    else {
        return """
        # Error

        Unable to load \(name).md
        """
    }

    return (
        try? String(
            contentsOf: url,
            encoding: .utf8
        )
    ) ?? """
    # Error

    Unable to load \(name).md
    """
}

func bundleImage(
    _ name: String
) -> NSImage? {
    guard let url =
        Bundle.main.url(
            forResource: name,
            withExtension: "png"
        )
    else {
        return nil
    }

    return NSImage(contentsOf: url)
}

// MARK: - Main

let app = NSApplication.shared

let delegate = AppDelegate()

app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(
    ignoringOtherApps: true
)
app.run()
