#include <cstdlib>
#include <cctype>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>
#include <sys/wait.h>

namespace {

std::string trim(const std::string &s) {
  size_t b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) {
    return "";
  }
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

std::string shellEscape(const std::string &in) {
  std::string out = "'";
  for (char c : in) {
    if (c == '\'') {
      out += "'\\''";
    } else {
      out.push_back(c);
    }
  }
  out.push_back('\'');
  return out;
}

std::string upperCopy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return value;
}

std::string readLine(const std::string &prompt, const std::string &def = "") {
  std::cout << prompt;
  if (!def.empty()) {
    std::cout << " [" << def << "]";
  }
  std::cout << ": ";
  std::string line;
  std::getline(std::cin, line);
  line = trim(line);
  if (line.empty()) {
    return def;
  }
  return line;
}

std::string readOptionalLine(const std::string &prompt, const std::string &suggested = "") {
  std::cout << prompt;
  if (!suggested.empty()) {
    std::cout << " [" << suggested << "]";
  }
  std::cout << " (Enter=none";
  if (!suggested.empty()) {
    std::cout << ", .=use shown value";
  }
  std::cout << "): ";
  std::string line;
  std::getline(std::cin, line);
  line = trim(line);
  if (line == "." && !suggested.empty()) {
    return suggested;
  }
  return line;
}

bool commandExists(const std::string &name);

int normalizeProcessStatus(int rawStatus) {
  if (rawStatus == -1) {
    return 127;
  }
  int rc = rawStatus;
#ifdef WIFEXITED
  if (WIFEXITED(rawStatus)) {
    rc = WEXITSTATUS(rawStatus);
  } else if (WIFSIGNALED(rawStatus)) {
    rc = 128 + WTERMSIG(rawStatus);
  }
#endif
  return rc;
}

bool isExecutableFile(const std::filesystem::path &path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    return false;
  }
  return ::access(path.c_str(), X_OK) == 0;
}

std::string findExecutableOnPath(const std::string &name) {
  if (name.empty()) {
    return "";
  }
  std::filesystem::path candidate(name);
  if (candidate.is_absolute() || name.find('/') != std::string::npos) {
    return isExecutableFile(candidate) ? candidate.string() : "";
  }

  const char *pathEnv = std::getenv("PATH");
  if (!pathEnv || !*pathEnv) {
    return "";
  }
  std::stringstream pathStream(pathEnv);
  std::string entry;
  while (std::getline(pathStream, entry, ':')) {
    std::filesystem::path dir = entry.empty() ? std::filesystem::current_path() : std::filesystem::path(entry);
    std::filesystem::path full = dir / name;
    if (isExecutableFile(full)) {
      return full.string();
    }
  }
  return "";
}

std::string preferredShellPath() {
  static const std::string resolved = []() -> std::string {
    const char *overrideShell = std::getenv("PRIVACYNODE_LAUNCHER_SHELL");
    if (overrideShell && *overrideShell) {
      std::string found = findExecutableOnPath(overrideShell);
      if (!found.empty()) {
        return found;
      }
    }

    const char *envShell = std::getenv("SHELL");
    if (envShell && *envShell) {
      std::string found = findExecutableOnPath(envShell);
      if (!found.empty()) {
        return found;
      }
    }

    for (const char *name : {"bash", "sh", "zsh"}) {
      std::string found = findExecutableOnPath(name);
      if (!found.empty()) {
        return found;
      }
    }
    return "";
  }();
  return resolved;
}

int executeShellCommand(const std::string &cmd) {
  const std::string shell = preferredShellPath();
  if (shell.empty()) {
    return 127;
  }

  std::cout.flush();
  std::cerr.flush();

  pid_t pid = fork();
  if (pid < 0) {
    return 127;
  }
  if (pid == 0) {
    execl(shell.c_str(), shell.c_str(), "-lc", cmd.c_str(), static_cast<char *>(nullptr));
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return 127;
  }
  return normalizeProcessStatus(status);
}

std::string captureShellCommandOutput(const std::string &cmd) {
  const std::string shell = preferredShellPath();
  if (shell.empty()) {
    return "";
  }

  int pipefd[2];
  if (pipe(pipefd) != 0) {
    return "";
  }

  std::cout.flush();
  std::cerr.flush();

  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return "";
  }
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    execl(shell.c_str(), shell.c_str(), "-lc", cmd.c_str(), static_cast<char *>(nullptr));
    _exit(127);
  }

  close(pipefd[1]);
  std::string output;
  char buffer[256];
  ssize_t n = 0;
  while ((n = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
    output.append(buffer, static_cast<size_t>(n));
  }
  close(pipefd[0]);

  int status = 0;
  waitpid(pid, &status, 0);
  return trim(output);
}

int runCommand(const std::string &cmd) {
  std::cout << "\n$ " << cmd << "\n\n" << std::flush;
  int rc = executeShellCommand(cmd);
  if (rc == 127 && preferredShellPath().empty()) {
    std::cout << "no usable shell found in PATH for launcher command execution\n";
  } else if (rc == -1) {
    std::cout << "command failed to start\n";
    return 127;
  }
  if (rc != 0) {
    std::cout << "command failed with code " << rc << "\n";
    if (rc == 127) {
      std::cout << "hint: command not found in this environment. "
                   "On Ubuntu, run: ./scripts/easy_node.sh install-deps-ubuntu\n";
    }
  }
  return rc;
}

bool ensureSudoAvailable(const std::string &context) {
  if (commandExists("sudo")) {
    return true;
  }
  std::cout << "sudo is not available for " << context
            << ". Run as root or install sudo.\n";
  return false;
}

int runCommandWithOptionalSudo(const std::string &cmd,
                               bool useSudo,
                               const std::string &context) {
  if (!useSudo) {
    return runCommand(cmd);
  }
  if (!ensureSudoAvailable(context)) {
    return 127;
  }
  return runCommand("sudo " + cmd);
}

int launchDetachedTerminalCommand(const std::string &title, const std::string &sessionCommand) {
  bool hasDisplay = false;
  const char *display = std::getenv("DISPLAY");
  const char *waylandDisplay = std::getenv("WAYLAND_DISPLAY");
  if ((display && *display) || (waylandDisplay && *waylandDisplay)) {
    hasDisplay = true;
  }
  if (!hasDisplay) {
    std::cout << "No GUI display detected; running session in current terminal.\n";
    return runCommand(sessionCommand);
  }

  struct Candidate {
    std::string binary;
    std::string command;
  };

  const std::string shell = preferredShellPath();
  if (shell.empty()) {
    std::cout << "No usable shell found in PATH; running session in current terminal.\n";
    return runCommand(sessionCommand);
  }

  std::vector<Candidate> candidates;
  if (commandExists("x-terminal-emulator")) {
    candidates.push_back({"x-terminal-emulator",
                          "x-terminal-emulator -e " + shellEscape(shell) +
                              " -lc " + shellEscape(sessionCommand)});
  }
  if (commandExists("gnome-terminal")) {
    candidates.push_back({"gnome-terminal",
                          "gnome-terminal --title=" + shellEscape(title) +
                          " -- " + shellEscape(shell) + " -lc " + shellEscape(sessionCommand)});
  }
  if (commandExists("konsole")) {
    candidates.push_back({"konsole",
                          "konsole --new-window -e " + shellEscape(shell) +
                              " -lc " + shellEscape(sessionCommand)});
  }
  if (commandExists("xfce4-terminal")) {
    candidates.push_back({"xfce4-terminal",
                          "xfce4-terminal --title=" + shellEscape(title) +
                          " -x " + shellEscape(shell) + " -lc " + shellEscape(sessionCommand)});
  }
  if (commandExists("xterm")) {
    candidates.push_back({"xterm",
                          "xterm -T " + shellEscape(title) + " -e " + shellEscape(shell) +
                              " -lc " + shellEscape(sessionCommand)});
  }
  if (commandExists("alacritty")) {
    candidates.push_back({"alacritty",
                          "alacritty --title " + shellEscape(title) + " -e " + shellEscape(shell) +
                              " -lc " + shellEscape(sessionCommand)});
  }

  for (const auto &candidate : candidates) {
    std::string detached = "nohup " + candidate.command + " >/dev/null 2>&1 < /dev/null &";
    std::cout << "\n$ " << detached << "\n\n" << std::flush;
    int rc = executeShellCommand(detached);
    if (rc == 0) {
      std::cout << "Launched " << title << " in a new terminal window.\n";
      return 0;
    }
  }

  std::cout << "Could not launch a terminal emulator; running session in current terminal.\n";
  return runCommand(sessionCommand);
}

int launchDetachedTerminalCommandWithOptionalSudo(const std::string &title,
                                                  const std::string &sessionCommand,
                                                  bool useSudo,
                                                  const std::string &context) {
  if (!useSudo) {
    return launchDetachedTerminalCommand(title, sessionCommand);
  }
  if (!ensureSudoAvailable(context)) {
    return 127;
  }
  return launchDetachedTerminalCommand(title, "sudo " + sessionCommand);
}

std::string captureCommandOutput(const std::string &cmd) {
  return captureShellCommandOutput(cmd);
}

bool commandExists(const std::string &name) {
  return !findExecutableOnPath(name).empty();
}

std::string readJsonStringField(const std::string &jsonPath, const std::string &expr) {
  if (jsonPath.empty() || !std::filesystem::exists(jsonPath) || !commandExists("jq")) {
    return "";
  }
  std::string cmd = "jq -r " + shellEscape(expr) + " " + shellEscape(jsonPath) + " 2>/dev/null";
  return captureCommandOutput(cmd);
}

void printManualValidationReportSummary(const std::string &summaryJsonPath) {
  if (summaryJsonPath.empty() || !std::filesystem::exists(summaryJsonPath)) {
    return;
  }

  std::string readinessStatus = readJsonStringField(summaryJsonPath, ".report.readiness_status // \"\"");
  std::string nextActionCommand = readJsonStringField(summaryJsonPath, ".summary.next_action_command // \"\"");
  std::string machineCSmokeReady = readJsonStringField(summaryJsonPath, "(.summary.pre_machine_c_gate.ready // false) | tostring");
  std::string machineCSmokeBlockers = readJsonStringField(summaryJsonPath, "(.summary.pre_machine_c_gate.blockers // []) | if length == 0 then \"none\" else join(\",\") end");
  std::string machineCSmokeNextCommand = readJsonStringField(summaryJsonPath, ".summary.pre_machine_c_gate.next_command // \"\"");
  std::string latestIncidentSummary = readJsonStringField(summaryJsonPath, ".summary.latest_failed_incident.summary_json.path // \"\"");
  std::string latestIncidentReport = readJsonStringField(summaryJsonPath, ".summary.latest_failed_incident.report_md.path // \"\"");
  std::string latestReadinessSummaryAttachment = readJsonStringField(summaryJsonPath, ".summary.latest_failed_incident.readiness_report_summary_attachment.bundle_path // \"\"");
  std::string latestReadinessReportAttachment = readJsonStringField(summaryJsonPath, ".summary.latest_failed_incident.readiness_report_md_attachment.bundle_path // \"\"");

  if (readinessStatus.empty() && nextActionCommand.empty() &&
      machineCSmokeReady.empty() && machineCSmokeBlockers.empty() &&
      machineCSmokeNextCommand.empty() &&
      latestIncidentSummary.empty() && latestIncidentReport.empty() &&
      latestReadinessSummaryAttachment.empty() &&
      latestReadinessReportAttachment.empty()) {
    return;
  }

  std::cout << "\nlauncher readiness summary\n";
  if (!readinessStatus.empty()) {
    std::cout << "  readiness_status=" << readinessStatus << "\n";
  }
  if (!nextActionCommand.empty()) {
    std::cout << "  next_action_command=" << nextActionCommand << "\n";
  }
  if (!machineCSmokeReady.empty()) {
    std::cout << "  machine_c_smoke_ready=" << machineCSmokeReady << "\n";
  }
  if (!machineCSmokeBlockers.empty()) {
    std::cout << "  machine_c_smoke_blockers=" << machineCSmokeBlockers << "\n";
  }
  if (!machineCSmokeNextCommand.empty()) {
    std::cout << "  machine_c_smoke_next_command=" << machineCSmokeNextCommand << "\n";
  }
  if (!latestIncidentSummary.empty()) {
    std::cout << "  latest_failed_incident_summary_json=" << latestIncidentSummary << "\n";
  }
  if (!latestIncidentReport.empty()) {
    std::cout << "  latest_failed_incident_report_md=" << latestIncidentReport << "\n";
  }
  if (!latestReadinessSummaryAttachment.empty()) {
    std::cout << "  latest_failed_incident_readiness_report_summary_attachment="
              << latestReadinessSummaryAttachment << "\n";
  }
  if (!latestReadinessReportAttachment.empty()) {
    std::cout << "  latest_failed_incident_readiness_report_md_attachment="
              << latestReadinessReportAttachment << "\n";
  }
  std::cout << std::flush;
}

std::string executableDir() {
  char path[4096];
  ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
  if (n <= 0) {
    return "";
  }
  path[n] = '\0';
  std::filesystem::path p(path);
  return p.parent_path().string();
}

std::string detectRepoRoot() {
  const char *env = std::getenv("PRIVACYNODE_ROOT");
  if (env && *env) {
    return std::string(env);
  }

  std::string exedir = executableDir();
  if (!exedir.empty()) {
    std::filesystem::path p = std::filesystem::path(exedir).parent_path();
    if (std::filesystem::exists(p / "scripts" / "easy_node.sh")) {
      return p.string();
    }
  }

  std::filesystem::path cwd = std::filesystem::current_path();
  if (std::filesystem::exists(cwd / "scripts" / "easy_node.sh")) {
    return cwd.string();
  }

  return "";
}

std::string resolveRepoPath(const std::string &root, const std::string &path) {
  if (path.empty()) {
    return "";
  }
  std::filesystem::path p(path);
  if (p.is_absolute()) {
    return p.string();
  }
  if (root.empty()) {
    return p.string();
  }
  return (std::filesystem::path(root) / p).string();
}

void showThreeMachineGuide() {
  std::cout << "\n3-machine quick flow\n";
  std::cout << "1) Machine A: server-up with A public IP/host and --beta-profile (IDs auto-generated)\n";
  std::cout << "2) Machine B: server-up with B public IP/host, --peer-directories=http://A:8081 and --beta-profile\n";
  std::cout << "3) Machine A (optional): rerun server-up with --peer-directories=http://B:8081\n";
  std::cout << "4) Machine C: client-vpn-up for real VPN usage (or client-test for quick dry-run)\n";
  std::cout << "5) One-IP mode: use machine-C bootstrap discovery from one known directory URL\n";
  std::cout << "6) Run full production sequence from machine C: three-machine-prod-bundle\n";
  std::cout << "7) Success signal: client log has selections and real WG shows handshake+transfer\n\n";
}

bool isRootUser() {
  return geteuid() == 0;
}

bool parseYesNo(const std::string &v, bool def) {
  std::string t = trim(v);
  if (t.empty()) {
    return def;
  }
  char c = static_cast<char>(std::tolower(static_cast<unsigned char>(t[0])));
  return c == 'y' || c == '1' || c == 't';
}

struct PathProfile {
  std::string label;
  bool distinctOperators;
  bool distinctCountries;
  bool localitySoftBias;
  std::string countryBias;
  std::string regionBias;
  std::string regionPrefixBias;
};

PathProfile choosePathProfile(const std::string &prompt = "Path profile (1=Fast, 2=Balanced, 3=Privacy)", const std::string &def = "2") {
  std::cout << "Path profile presets:\n";
  std::cout << "  1) Fast      : lower latency, soft-locality bias enabled, distinct operators\n";
  std::cout << "  2) Balanced  : moderate locality bias, distinct operators\n";
  std::cout << "  3) Privacy   : enforce distinct countries, locality bias disabled\n";
  std::string choice = trim(readLine(prompt, def));
  if (choice != "1" && choice != "2" && choice != "3") {
    std::cout << "invalid profile choice; using Balanced\n";
    choice = "2";
  }
  if (choice == "1") {
    return {"fast", true, false, true, "1.80", "1.35", "1.15"};
  }
  if (choice == "3") {
    return {"privacy", true, true, false, "1.60", "1.25", "1.10"};
  }
  return {"balanced", true, false, true, "1.50", "1.25", "1.10"};
}

void appendPathProfileFlags(std::ostringstream &cmd, const PathProfile &profile) {
  cmd << " --distinct-operators " << (profile.distinctOperators ? "1" : "0")
      << " --distinct-countries " << (profile.distinctCountries ? "1" : "0")
      << " --locality-soft-bias " << (profile.localitySoftBias ? "1" : "0")
      << " --country-bias " << shellEscape(profile.countryBias)
      << " --region-bias " << shellEscape(profile.regionBias)
      << " --region-prefix-bias " << shellEscape(profile.regionPrefixBias);
}

struct TestSuite {
  std::string name;
  std::string command;
  bool privileged;
};

struct ABHosts {
  std::string aHost;
  std::string bHost;
};

std::string hostsConfigPath(const std::string &root) {
  return (std::filesystem::path(root) / "data" / "easy_mode_hosts.conf").string();
}

std::string serverModePath(const std::string &root) {
  return (std::filesystem::path(root) / "deploy" / "data" / "easy_node_server_mode.conf").string();
}

std::string loadServerMode(const std::string &root) {
  std::ifstream in(serverModePath(root));
  if (!in.is_open()) {
    return "";
  }
  std::string line;
  while (std::getline(in, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '#') {
      continue;
    }
    if (line.rfind("EASY_NODE_SERVER_MODE=", 0) == 0) {
      return trim(line.substr(std::string("EASY_NODE_SERVER_MODE=").size()));
    }
  }
  return "";
}

std::string stripSchemeAndPath(const std::string &raw) {
  std::string v = trim(raw);
  if (v.empty()) {
    return "";
  }
  const std::string http = "http://";
  const std::string https = "https://";
  if (v.rfind(http, 0) == 0) {
    v = v.substr(http.size());
  } else if (v.rfind(https, 0) == 0) {
    v = v.substr(https.size());
  }
  size_t slash = v.find('/');
  if (slash != std::string::npos) {
    v = v.substr(0, slash);
  }
  return trim(v);
}

std::string normalizePublicHostInput(const std::string &raw) {
  std::string v = stripSchemeAndPath(raw);
  if (v.empty()) {
    return "";
  }
  if (v.front() == '[') {
    size_t close = v.find(']');
    if (close != std::string::npos) {
      return trim(v.substr(0, close + 1));
    }
    return trim(v);
  }
  size_t colonCount = static_cast<size_t>(std::count(v.begin(), v.end(), ':'));
  if (colonCount == 1) {
    size_t pos = v.rfind(':');
    std::string maybePort = v.substr(pos + 1);
    bool allDigits = !maybePort.empty() &&
                     std::all_of(maybePort.begin(), maybePort.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
    if (allDigits) {
      v = v.substr(0, pos);
    }
  }
  return trim(v);
}

std::string normalizeEndpointURL(const std::string &raw, int defaultPort) {
  std::string v = trim(raw);
  if (v.empty()) {
    return "";
  }
  v = stripSchemeAndPath(v);
  if (v.empty()) {
    return "";
  }

  bool hasPort = false;
  if (v.front() == '[') {
    hasPort = (v.find("]:") != std::string::npos);
  } else {
    size_t colonCount = static_cast<size_t>(std::count(v.begin(), v.end(), ':'));
    hasPort = (colonCount == 1);
  }
  if (!hasPort && defaultPort > 0) {
    std::ostringstream withPort;
    withPort << v << ":" << defaultPort;
    v = withPort.str();
  }

  return "http://" + v;
}

std::string endpointFromHost(const std::string &host, int port) {
  std::ostringstream ss;
  ss << "http://" << host << ":" << port;
  return ss.str();
}

void appendOptionalAdminAuthArgs(std::ostringstream &cmd) {
  std::string adminToken = trim(readLine("Admin token (optional; blank=auto from local authority env)", ""));
  bool useSigned = parseYesNo(readLine("Use signed admin key auth? (y/N)", "n"), false);
  if (useSigned) {
    std::string keyFile = trim(readLine("Admin signing private key file", ""));
    std::string keyId = trim(readLine("Admin signing key id", ""));
    if (!keyFile.empty() && !keyId.empty()) {
      cmd << " --admin-key-file " << shellEscape(keyFile)
          << " --admin-key-id " << shellEscape(keyId);
    } else {
      std::cout << "signed auth not fully provided; falling back to token/env auth\n";
    }
  } else if (!adminToken.empty()) {
    cmd << " --admin-token " << shellEscape(adminToken);
  }
}

ABHosts loadABHosts(const std::string &root) {
  ABHosts out;
  std::ifstream in(hostsConfigPath(root));
  if (!in.is_open()) {
    return out;
  }
  std::string line;
  while (std::getline(in, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '#') {
      continue;
    }
    size_t eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    std::string k = trim(line.substr(0, eq));
    std::string v = normalizePublicHostInput(line.substr(eq + 1));
    if (k == "MACHINE_A_HOST") {
      out.aHost = v;
    } else if (k == "MACHINE_B_HOST") {
      out.bHost = v;
    }
  }
  return out;
}

bool saveABHosts(const std::string &root, const ABHosts &hosts) {
  std::filesystem::path dataDir = std::filesystem::path(root) / "data";
  std::error_code ec;
  std::filesystem::create_directories(dataDir, ec);

  std::ofstream out(hostsConfigPath(root), std::ios::trunc);
  if (!out.is_open()) {
    return false;
  }
  out << "MACHINE_A_HOST=" << hosts.aHost << "\n";
  out << "MACHINE_B_HOST=" << hosts.bHost << "\n";
  return true;
}

bool hasBothHosts(const ABHosts &hosts) {
  return !trim(hosts.aHost).empty() && !trim(hosts.bHost).empty();
}

void configureABHostsInteractive(const std::string &root, ABHosts &hosts, bool forcePrompt) {
  bool promptForUpdate = forcePrompt || !hasBothHosts(hosts);
  if (!promptForUpdate) {
    std::ostringstream prompt;
    prompt << "Use saved machine hosts? A=" << hosts.aHost << " B=" << hosts.bHost << " (Y/n)";
    bool keep = parseYesNo(readLine(prompt.str(), "y"), true);
    if (keep) {
      return;
    }
  }
  hosts.aHost = normalizePublicHostInput(readLine("Machine A IP/host", hosts.aHost));
  hosts.bHost = normalizePublicHostInput(readLine("Machine B IP/host", hosts.bHost));
  if (!hasBothHosts(hosts)) {
    std::cout << "both Machine A and Machine B hosts are required\n";
    return;
  }
  if (!saveABHosts(root, hosts)) {
    std::cout << "warning: could not save host config file\n";
  } else {
    std::cout << "saved host config: " << hostsConfigPath(root) << "\n";
  }
}

int runTestSuites(const std::string &root, const std::vector<TestSuite> &suites, bool allowSudo) {
  int passed = 0;
  int failed = 0;
  int skipped = 0;

  for (const auto &suite : suites) {
    std::cout << "\n[Test] " << suite.name << "\n" << std::flush;

    std::string cmd = "cd " + shellEscape(root) + " && ";
    if (suite.privileged && !isRootUser()) {
      if (allowSudo) {
        cmd += "sudo ";
      } else {
        std::cout << "skipped (requires root privileges)\n";
        skipped++;
        continue;
      }
    }
    cmd += suite.command;

    int rc = runCommand(cmd);
    if (rc == 0) {
      passed++;
      std::cout << "[PASS] " << suite.name << "\n";
    } else {
      failed++;
      std::cout << "[FAIL] " << suite.name << "\n";
    }
  }

  std::cout << "\nTest summary: passed=" << passed << " failed=" << failed << " skipped=" << skipped << "\n";
  return failed;
}

void showTestMenu() {
  std::cout << "\nChoose test profile:\n";
  std::cout << "1) Unit tests (go test ./...)\n";
  std::cout << "2) Local CI suite (scripts/ci_local.sh)\n";
  std::cout << "3) Beta preflight (scripts/beta_preflight.sh)\n";
  std::cout << "4) Deep test suite (scripts/deep_test_suite.sh)\n";
  std::cout << "5) Real WG privileged check (integration_real_wg_privileged.sh)\n";
  std::cout << "6) Real WG privileged matrix (integration_real_wg_privileged_matrix.sh)\n";
  std::cout << "7) Recommended beta set (unit + beta preflight)\n";
  std::cout << "8) Machine A server test\n";
  std::cout << "9) Machine B federation test\n";
  std::cout << "10) Machine C full cross-network test\n";
  std::cout << "11) Machine C soak/fault test\n";
  std::cout << "0) Back\n";
}

void runTestsInteractive(const std::string &root, const std::string &script, ABHosts &hosts) {
  for (;;) {
    showTestMenu();
    std::cout << "Selection: ";

    std::string choice;
    std::getline(std::cin, choice);
    choice = trim(choice);

    if (choice == "0") {
      return;
    }

    bool allowSudo = false;
    if (choice == "5" || choice == "6") {
      allowSudo = parseYesNo(readLine("Use sudo for privileged test? (y/N)", "n"), false);
    }

    std::vector<TestSuite> suites;
    if (choice == "1") {
      suites.push_back({"Unit tests", "go test ./...", false});
    } else if (choice == "2") {
      suites.push_back({"Local CI suite", "./scripts/ci_local.sh", false});
    } else if (choice == "3") {
      suites.push_back({"Beta preflight", "./scripts/beta_preflight.sh", false});
    } else if (choice == "4") {
      suites.push_back({"Deep test suite", "./scripts/deep_test_suite.sh", false});
    } else if (choice == "5") {
      suites.push_back({"Real WG privileged check", "./scripts/integration_real_wg_privileged.sh", true});
    } else if (choice == "6") {
      suites.push_back({"Real WG privileged matrix", "./scripts/integration_real_wg_privileged_matrix.sh", true});
    } else if (choice == "7") {
      suites.push_back({"Unit tests", "go test ./...", false});
      suites.push_back({"Beta preflight", "./scripts/beta_preflight.sh", false});
    } else if (choice == "8") {
      configureABHostsInteractive(root, hosts, false);
      std::string host = normalizePublicHostInput(readLine("Machine A public host/IP (optional)", hosts.aHost));
      std::string report = readLine("Report file path (optional)", "");
      std::ostringstream cmd;
      cmd << shellEscape(script) << " machine-a-test";
      if (!host.empty()) {
        cmd << " --public-host " << shellEscape(host);
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      suites.push_back({"Machine A server test", cmd.str(), false});
    } else if (choice == "9") {
      configureABHostsInteractive(root, hosts, false);
      std::string peerA = normalizeEndpointURL(readLine("Machine A directory URL", endpointFromHost(hosts.aHost, 8081)), 8081);
      std::string host = normalizePublicHostInput(readLine("Machine B public host/IP (optional)", hosts.bHost));
      std::string minOperators = readLine("Minimum operators on machine B", "2");
      std::string federationTimeout = readLine("Federation wait timeout sec", "90");
      std::string report = readLine("Report file path (optional)", "");
      if (peerA.empty()) {
        std::cout << "machine A directory URL is required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " machine-b-test"
          << " --peer-directory-a " << shellEscape(peerA)
          << " --min-operators " << shellEscape(minOperators)
          << " --federation-timeout-sec " << shellEscape(federationTimeout);
      if (!host.empty()) {
        cmd << " --public-host " << shellEscape(host);
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      suites.push_back({"Machine B federation test", cmd.str(), false});
    } else if (choice == "10") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "12";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "12");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string minSources = readLine("Minimum directory sources", "2");
      std::string minOperators = readLine("Minimum operators per directory", "2");
      std::string federationTimeout = readLine("Federation wait timeout sec", "90");
      std::string timeoutSec = readLine("Client validation timeout sec", "50");
      std::string country = readLine("Preferred exit country code (optional)", "");
      std::string region = readLine("Preferred exit region (optional)", "");
      bool betaProfile = parseYesNo(readLine("Enable beta profile defaults? (Y/n)", "y"), true);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      PathProfile pathProfile = choosePathProfile("Path profile for machine C test (1=Fast, 2=Balanced, 3=Privacy)", "2");
      bool distinct = pathProfile.distinctOperators;
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
        pathProfile.distinctOperators = true;
      }
      std::string report = readLine("Report file path (optional)", "");
      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " machine-c-test"
          << " --min-sources " << shellEscape(minSources)
          << " --min-operators " << shellEscape(minOperators)
          << " --federation-timeout-sec " << shellEscape(federationTimeout)
          << " --timeout-sec " << shellEscape(timeoutSec)
          << " --beta-profile " << (betaProfile ? "1" : "0")
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --distinct-operators " << (distinct ? "1" : "0");
      cmd << " --distinct-countries " << (pathProfile.distinctCountries ? "1" : "0")
          << " --locality-soft-bias " << (pathProfile.localitySoftBias ? "1" : "0")
          << " --country-bias " << shellEscape(pathProfile.countryBias)
          << " --region-bias " << shellEscape(pathProfile.regionBias)
          << " --region-prefix-bias " << shellEscape(pathProfile.regionPrefixBias);
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --discovery-wait-sec " << shellEscape(discoveryWait);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!country.empty()) {
        cmd << " --exit-country " << shellEscape(country);
      }
      if (!region.empty()) {
        cmd << " --exit-region " << shellEscape(region);
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      suites.push_back({"Machine C cross-network test", cmd.str(), false});
    } else if (choice == "11") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "12";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "12");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string rounds = readLine("Soak rounds", "10");
      std::string pauseSec = readLine("Pause between rounds sec", "5");
      std::string minSources = readLine("Minimum directory sources", "2");
      std::string minOperators = readLine("Minimum operators per directory", "2");
      std::string federationTimeout = readLine("Federation wait timeout sec", "90");
      std::string timeoutSec = readLine("Client validation timeout sec", "50");
      std::string faultEvery = readLine("Inject fault every N rounds (0=off)", "0");
      std::string faultCommand = readLine("Fault command (optional)", "");
      bool continueOnFail = parseYesNo(readLine("Continue when a round fails? (y/N)", "n"), false);
      bool betaProfile = parseYesNo(readLine("Enable beta profile defaults? (Y/n)", "y"), true);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      PathProfile pathProfile = choosePathProfile("Path profile for machine C soak (1=Fast, 2=Balanced, 3=Privacy)", "2");
      bool distinct = pathProfile.distinctOperators;
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
        pathProfile.distinctOperators = true;
      }
      std::string country = readLine("Preferred exit country code (optional)", "");
      std::string region = readLine("Preferred exit region (optional)", "");
      std::string report = readLine("Report file path (optional)", "");
      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << "./scripts/integration_3machine_beta_soak.sh"
          << " --rounds " << shellEscape(rounds)
          << " --pause-sec " << shellEscape(pauseSec)
          << " --min-sources " << shellEscape(minSources)
          << " --min-operators " << shellEscape(minOperators)
          << " --federation-timeout-sec " << shellEscape(federationTimeout)
          << " --timeout-sec " << shellEscape(timeoutSec)
          << " --continue-on-fail " << (continueOnFail ? "1" : "0")
          << " --beta-profile " << (betaProfile ? "1" : "0")
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --distinct-operators " << (distinct ? "1" : "0");
      cmd << " --distinct-countries " << (pathProfile.distinctCountries ? "1" : "0")
          << " --locality-soft-bias " << (pathProfile.localitySoftBias ? "1" : "0")
          << " --country-bias " << shellEscape(pathProfile.countryBias)
          << " --region-bias " << shellEscape(pathProfile.regionBias)
          << " --region-prefix-bias " << shellEscape(pathProfile.regionPrefixBias);
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --discovery-wait-sec " << shellEscape(discoveryWait);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!faultEvery.empty()) {
        cmd << " --fault-every " << shellEscape(faultEvery);
      }
      if (!faultCommand.empty()) {
        cmd << " --fault-command " << shellEscape(faultCommand);
      }
      if (!country.empty()) {
        cmd << " --exit-country " << shellEscape(country);
      }
      if (!region.empty()) {
        cmd << " --exit-region " << shellEscape(region);
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      suites.push_back({"Machine C soak/fault test", cmd.str(), false});
    } else {
      std::cout << "invalid selection\n";
      continue;
    }

    int failed = runTestSuites(root, suites, allowSudo);
    if (failed == 0) {
      std::cout << "overall result: PASS\n";
    } else {
      std::cout << "overall result: FAIL\n";
    }
  }
}

void quickClientConnect(const std::string &script, ABHosts &hosts) {
  std::string defaultBootstrap = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) :
                                 (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
  std::string bootstrapDir = normalizeEndpointURL(readLine("Server IP/host or bootstrap URL", defaultBootstrap), 8081);
  std::string inviteKey = trim(readLine("Invite key", ""));
  std::string discoveryWait = readLine("Discovery wait sec", "20");
  bool prodProfile = parseYesNo(readLine("Use PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
  PathProfile pathProfile = choosePathProfile("Client path profile (1=Fast, 2=Balanced, 3=Privacy)", "2");
  bool realVPN = parseYesNo(readLine("Run real VPN mode (host WireGuard interface)? (Y/n)", "y"), true);
  if (bootstrapDir.empty()) {
    std::cout << "server IP/host is required\n";
    return;
  }
  if (inviteKey.empty()) {
    std::cout << "invite key is required\n";
    return;
  }
  std::ostringstream cmd;
  if (realVPN) {
    std::string iface = trim(readLine("VPN interface name", "wgvpn0"));
    std::string readyTimeout = readLine("VPN ready timeout sec", "35");
    bool runPreflight = parseYesNo(readLine("Run VPN preflight first? (Y/n)", "y"), true);
    if (runPreflight) {
      std::ostringstream preflightCmd;
      preflightCmd << shellEscape(script) << " client-vpn-preflight"
                   << " --bootstrap-directory " << shellEscape(bootstrapDir)
                   << " --discovery-wait-sec " << shellEscape(discoveryWait)
                   << " --prod-profile " << (prodProfile ? "1" : "0")
                   << " --interface " << shellEscape(iface);
      if (pathProfile.distinctOperators) {
        preflightCmd << " --operator-floor-check 1";
      }
      if (!isRootUser()) {
        bool useSudoPreflight = parseYesNo(readLine("Run preflight with sudo? (Y/n)", "y"), true);
        if (runCommandWithOptionalSudo(preflightCmd.str(), useSudoPreflight, "client preflight") != 0) {
          std::cout << "preflight failed; stopping client connect flow\n";
          return;
        }
      } else {
        if (runCommand(preflightCmd.str()) != 0) {
          std::cout << "preflight failed; stopping client connect flow\n";
          return;
        }
      }
    }
    bool openTerminal = parseYesNo(
        readLine("Open dedicated CLIENT terminal with live logs + auto cleanup on close? (Y/n)", "y"), true);
    cmd << shellEscape(script) << " client-vpn-session"
        << " --bootstrap-directory " << shellEscape(bootstrapDir)
        << " --discovery-wait-sec " << shellEscape(discoveryWait)
        << " --subject " << shellEscape(inviteKey)
        << " --min-sources 1"
        << " --min-operators 1"
        << " --beta-profile 1"
        << " --prod-profile " << (prodProfile ? "1" : "0")
        << " --interface " << shellEscape(iface)
        << " --ready-timeout-sec " << shellEscape(readyTimeout)
        << " --cleanup-all 1";
    appendPathProfileFlags(cmd, pathProfile);
    if (!isRootUser()) {
      bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
      if (openTerminal) {
        launchDetachedTerminalCommandWithOptionalSudo("Privacynode CLIENT session",
                                                     cmd.str(),
                                                     useSudo,
                                                     "client session");
      } else {
        runCommandWithOptionalSudo(cmd.str(), useSudo, "client session");
      }
    } else {
      if (openTerminal) {
        launchDetachedTerminalCommand("Privacynode CLIENT session", cmd.str());
      } else {
        runCommand(cmd.str());
      }
    }
    std::cout << "Use Other options -> 32 (status) and 33 (down); option 31 reruns preflight.\n";
  } else {
    std::string timeoutSec = readLine("Connection timeout sec", "45");
    cmd << shellEscape(script) << " client-test"
        << " --bootstrap-directory " << shellEscape(bootstrapDir)
        << " --discovery-wait-sec " << shellEscape(discoveryWait)
        << " --subject " << shellEscape(inviteKey)
        << " --min-sources 1"
        << " --timeout-sec " << shellEscape(timeoutSec)
        << " --beta-profile 1"
        << " --prod-profile " << (prodProfile ? "1" : "0");
    appendPathProfileFlags(cmd, pathProfile);
    runCommand(cmd.str());
  }
}

void quickServerConnect(const std::string &root, const std::string &script, ABHosts &hosts) {
  std::string hostDefault = !hosts.aHost.empty() ? hosts.aHost : (!hosts.bHost.empty() ? hosts.bHost : "");
  std::string host = normalizePublicHostInput(readLine("Public host/IP for this server", hostDefault));
  bool authorityMode = parseYesNo(readLine("Is this your AUTHORITY admin machine? (y/N)", "n"), false);
  if (authorityMode) {
    bool confirmAuthority = parseYesNo(readLine("Authority mode can create/disable invite keys. Continue? (y/N)", "n"), false);
    if (!confirmAuthority) {
      authorityMode = false;
      std::cout << "using provider mode\n";
    }
  }
  std::string peerDefault = "";
  if (!host.empty() && host == hosts.aHost && !hosts.bHost.empty()) {
    peerDefault = hosts.bHost;
  } else if (!host.empty() && host == hosts.bHost && !hosts.aHost.empty()) {
    peerDefault = hosts.aHost;
  }
  std::string peerHost = normalizePublicHostInput(readOptionalLine("Peer server IP/host (optional)", peerDefault));
  if (host.empty()) {
    std::cout << "public host/IP is required\n";
    return;
  }
  bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
  bool runPreflight = parseYesNo(readLine("Run server preflight before startup? (Y/n)", "y"), true);
  std::string peerIdentityStrict = trim(readLine("Peer identity strict mode (auto/1/0)", "auto"));
  if (peerIdentityStrict != "auto" && peerIdentityStrict != "1" && peerIdentityStrict != "0") {
    std::cout << "invalid peer identity strict mode; using auto\n";
    peerIdentityStrict = "auto";
  }
  std::string preflightTimeout = readLine("Preflight timeout sec", "8");

  std::string modeValue = authorityMode ? "authority" : "provider";
  std::string peerDirectoriesArg = "";
  std::string authorityDir = "";
  std::string authorityIssuer = "";

  std::ostringstream cmd;
  cmd << shellEscape(script) << " server-session"
      << " --mode " << modeValue
      << " --public-host " << shellEscape(host)
      << " --beta-profile 1"
      << " --prod-profile " << (prodProfile ? "1" : "0")
      << " --peer-identity-strict " << shellEscape(peerIdentityStrict)
      << " --cleanup-all 1";
  if (authorityMode) {
    cmd << " --client-allowlist 1"
        << " --allow-anon-cred 0";
    if (!peerHost.empty()) {
      peerDirectoriesArg = endpointFromHost(peerHost, 8081);
      cmd << " --peer-directories " << shellEscape(peerDirectoriesArg);
    }
  } else {
    std::string authorityDirDefault = !peerHost.empty() ? endpointFromHost(peerHost, 8081) : "";
    authorityDir = normalizeEndpointURL(readLine("Authority directory URL", authorityDirDefault), 8081);
    std::string authorityIssuerDefault = "";
    if (!authorityDir.empty()) {
      std::string authorityHost = normalizePublicHostInput(authorityDir);
      authorityHost = stripSchemeAndPath(authorityHost);
      if (!authorityHost.empty()) {
        authorityIssuerDefault = endpointFromHost(normalizePublicHostInput(authorityHost), 8082);
      }
    }
    authorityIssuer = normalizeEndpointURL(readLine("Authority issuer URL", authorityIssuerDefault), 8082);
    if (authorityDir.empty() || authorityIssuer.empty()) {
      std::cout << "authority directory and issuer URLs are required for provider mode\n";
      return;
    }
    peerDirectoriesArg = authorityDir;
    cmd << " --authority-directory " << shellEscape(authorityDir)
        << " --authority-issuer " << shellEscape(authorityIssuer)
        << " --peer-directories " << shellEscape(peerDirectoriesArg);
  }

  if (runPreflight) {
    std::string minPeerOpsDefault = peerDirectoriesArg.empty() ? "0" : "1";
    std::string minPeerOps = readLine("Preflight minimum distinct peer operators", minPeerOpsDefault);
    std::ostringstream preflightCmd;
    preflightCmd << shellEscape(script) << " server-preflight"
                 << " --mode " << shellEscape(modeValue)
                 << " --public-host " << shellEscape(host)
                 << " --beta-profile 1"
                 << " --prod-profile " << (prodProfile ? "1" : "0")
                 << " --peer-identity-strict " << shellEscape(peerIdentityStrict)
                 << " --min-peer-operators " << shellEscape(minPeerOps)
                 << " --timeout-sec " << shellEscape(preflightTimeout);
    if (!peerDirectoriesArg.empty()) {
      preflightCmd << " --peer-directories " << shellEscape(peerDirectoriesArg);
    }
    if (!authorityDir.empty()) {
      preflightCmd << " --authority-directory " << shellEscape(authorityDir);
    }
    if (!authorityIssuer.empty()) {
      preflightCmd << " --authority-issuer " << shellEscape(authorityIssuer);
    }
    if (runCommand(preflightCmd.str()) != 0) {
      std::cout << "server preflight failed; not starting server-up\n";
      return;
    }
  }

  bool openTerminal = parseYesNo(
      readLine("Open dedicated SERVER terminal with live logs + auto cleanup on close? (Y/n)", "y"), true);
  bool useSudo = false;
  if (!isRootUser()) {
    useSudo = parseYesNo(readLine("Run server session with sudo? (y/N)", "n"), false);
  }

  int rc = 0;
  bool launchedSession = false;
  if (openTerminal) {
    rc = launchDetachedTerminalCommandWithOptionalSudo("Privacynode SERVER session",
                                                       cmd.str(),
                                                       useSudo,
                                                       "server session");
    launchedSession = (rc == 0);
  } else {
    rc = runCommandWithOptionalSudo(cmd.str(), useSudo, "server session");
  }

  bool saveHosts = parseYesNo(readLine("Save/update Machine A/B host config? (y/N)", "n"), false);
  if (saveHosts) {
    configureABHostsInteractive(root, hosts, true);
  }

  if (launchedSession && authorityMode) {
    std::cout << "server session launched. Generate invite keys after startup from Other options -> 7.\n";
  } else if (launchedSession) {
    std::cout << "provider session launched (no local admin/invite controls).\n";
  } else if (rc == 0 && authorityMode) {
    bool genInvite = parseYesNo(readLine("Generate invite key now? (Y/n)", "y"), true);
    if (genInvite) {
      std::string count = readLine("How many invite keys", "1");
      std::ostringstream inviteCmd;
      inviteCmd << shellEscape(script) << " invite-generate"
                << " --count " << shellEscape(count);
      runCommand(inviteCmd.str());
    }
  } else if (rc == 0) {
    std::cout << "provider mode started (no local admin/invite controls)\n";
  }
}

void runAdvancedMenu(const std::string &root, const std::string &script, ABHosts &hosts) {
  for (;;) {
    std::string serverMode = loadServerMode(root);
    std::cout << "\nAdvanced options:\n";
    if (serverMode == "authority" || serverMode == "provider") {
      std::cout << "Active server mode: " << serverMode << "\n";
    }
    std::cout << "1) Check dependencies\n";
    std::cout << "2) Install Ubuntu dependencies\n";
    std::cout << "3) Server status\n";
    std::cout << "4) Server logs\n";
    std::cout << "5) Stop server stack\n";
    std::cout << "6) Stop ALL local resources (docker + wg-only stack)\n";
    std::cout << "7) Generate invite key(s)\n";
    std::cout << "8) Check invite key\n";
    std::cout << "9) Disable invite key\n";
    std::cout << "10) Run 3-machine validation\n";
    std::cout << "11) Run 3-machine soak test\n";
    std::cout << "12) Run pilot runbook bundle\n";
    std::cout << "13) Run automated tests\n";
    std::cout << "14) Configure machine A/B hosts\n";
    std::cout << "15) Show 3-machine test guide\n";
    std::cout << "16) Bootstrap/rotate mTLS certs\n";
    std::cout << "17) Prod preflight check\n";
    std::cout << "18) Admin signing status\n";
    std::cout << "19) Rotate admin signing key\n";
    std::cout << "20) WG-only preflight (Linux/root)\n";
    std::cout << "21) WG-only local test (real WireGuard)\n";
    std::cout << "22) WG-only stack up (real WireGuard, background)\n";
    std::cout << "23) WG-only stack status\n";
    std::cout << "24) WG-only stack down\n";
    std::cout << "25) WG-only stack selftest (up->client test->down)\n";
    std::cout << "26) Rotate local server secrets\n";
    std::cout << "27) Real 3-machine PROD WG validate (Linux/root)\n";
    std::cout << "28) Real 3-machine PROD WG soak (Linux/root)\n";
    std::cout << "29) Full 3-machine PROD gate + diagnostics bundle\n";
    std::cout << "30) Show true 3-machine reminder checklist\n";
    std::cout << "31) Client VPN preflight (real mode)\n";
    std::cout << "32) Client VPN status (real mode)\n";
    std::cout << "33) Client VPN down (real mode)\n";
    std::cout << "34) Client VPN up (real mode, full manual)\n";
    std::cout << "35) Server preflight (peer/identity/quorum checks)\n";
    std::cout << "36) Closed-beta PROD bundle (strict preflight + integrity verify + signoff + run report + auto incident snapshot on fail)\n";
    std::cout << "37) Closed-beta PROD bundle (smoke + integrity verify + run report + auto incident snapshot on fail)\n";
    std::cout << "38) Verify PROD bundle integrity + gate artifacts\n";
    std::cout << "39) PROD pilot runbook (strict one-command defaults)\n";
    std::cout << "40) Capture incident snapshot bundle (debug/triage)\n";
    std::cout << "41) PROD gate SLO decision summary (GO/NO-GO)\n";
    std::cout << "42) PROD gate SLO trend (multi-run GO/NO-GO rate)\n";
    std::cout << "43) PROD gate SLO alert severity (OK/WARN/CRITICAL)\n";
    std::cout << "44) PROD SLO dashboard artifact (trend + alert + markdown)\n";
    std::cout << "45) PROD key-rotation runbook (backup + preflight + rollback)\n";
    std::cout << "46) PROD upgrade runbook (pull/build/restart + rollback)\n";
    std::cout << "47) PROD operator lifecycle runbook (onboard/offboard)\n";
    std::cout << "48) PROD pilot cohort runbook (multi-round sustained pilot)\n";
    std::cout << "49) PROD pilot cohort bundle verify\n";
    std::cout << "50) PROD pilot cohort signoff (integrity + policy)\n";
    std::cout << "51) PROD pilot cohort full flow (runbook + signoff)\n";
    std::cout << "52) PROD pilot cohort quick mode (minimal prompts)\n";
    std::cout << "53) PROD pilot cohort quick-check (verify quick run report)\n";
    std::cout << "54) PROD pilot cohort quick-trend (multi-run GO/NO-GO)\n";
    std::cout << "55) PROD pilot cohort quick-alert (OK/WARN/CRITICAL)\n";
    std::cout << "56) PROD pilot cohort quick-dashboard (trend + alert + markdown)\n";
    std::cout << "57) PROD pilot cohort quick-signoff (check + trend + alert gate)\n";
    std::cout << "58) PROD pilot cohort quick-runbook (quick + signoff + dashboard)\n";
    std::cout << "59) PROD pilot cohort campaign (strict low-prompt preset)\n";
    std::cout << "60) Runtime doctor (stale ports/interfaces/state preflight)\n";
    std::cout << "61) Show manual validation backlog reminder\n";
    std::cout << "62) Runtime fix (safe cleanup from doctor findings)\n";
    std::cout << "63) Manual validation status (live readiness + recorded receipts)\n";
    std::cout << "64) Client VPN smoke (preflight + up + status + optional egress check + receipt)\n";
    std::cout << "65) True 3-machine PROD signoff (bundle + receipt)\n";
    std::cout << "66) Manual validation report (markdown + JSON readiness handoff)\n";
    std::cout << "67) WG-only selftest + readiness receipt\n";
    std::cout << "68) Pre-real-host readiness sweep (runtime fix + WG-only + report)\n";
    std::cout << "0) Back\n";
    std::cout << "Selection: ";

    std::string choice;
    std::getline(std::cin, choice);
    choice = trim(choice);

    if (choice == "0") {
      return;
    }
    if (choice == "1") {
      int rc = runCommand(shellEscape(script) + " check");
      if (rc != 0) {
        bool installNow = parseYesNo(readLine("Install Ubuntu dependencies now? (y/N)", "n"), false);
        if (installNow) {
          runCommand(shellEscape(script) + " install-deps-ubuntu");
        }
      }
      continue;
    }
    if (choice == "2") {
      runCommand(shellEscape(script) + " install-deps-ubuntu");
      continue;
    }
    if (choice == "3") {
      runCommand(shellEscape(script) + " server-status");
      continue;
    }
    if (choice == "4") {
      runCommand(shellEscape(script) + " server-logs");
      continue;
    }
    if (choice == "5") {
      runCommand(shellEscape(script) + " server-down");
      continue;
    }
    if (choice == "6") {
      bool confirm = parseYesNo(readLine("Stop and remove all local Privacynode resources? (y/N)", "n"), false);
      if (confirm) {
        std::ostringstream cmd;
        cmd << shellEscape(script) << " stop-all"
            << " --with-wg-only 1"
            << " --force-iface-cleanup 1";
        bool hasWgState = std::filesystem::exists(std::filesystem::path(root) / "deploy" / "data" / "wg_only_stack.state");
        if (!isRootUser() && hasWgState) {
          bool useSudo = parseYesNo(readLine("WG-only stack detected. Run stop-all with sudo for full cleanup? (Y/n)", "y"), true);
          if (useSudo) {
            runCommand("sudo " + cmd.str());
          } else {
            runCommand(cmd.str());
          }
        } else {
          runCommand(cmd.str());
        }
      } else {
        std::cout << "cancelled\n";
      }
      continue;
    }
    if (choice == "7") {
      if (serverMode != "authority") {
        std::cout << "invite key management is authority-only. Start server in authority mode on your admin machine.\n";
        continue;
      }
      std::string count = readLine("How many keys", "1");
      std::string prefix = readLine("Key prefix", "inv");
      std::string tier = readLine("Tier (1/2/3)", "1");
      std::string issuer = normalizeEndpointURL(readLine("Issuer URL (optional)", ""), 8082);
      std::ostringstream cmd;
      cmd << shellEscape(script) << " invite-generate"
          << " --count " << shellEscape(count)
          << " --prefix " << shellEscape(prefix)
          << " --tier " << shellEscape(tier);
      if (!issuer.empty()) {
        cmd << " --issuer-url " << shellEscape(issuer);
      }
      appendOptionalAdminAuthArgs(cmd);
      runCommand(cmd.str());
      continue;
    }
    if (choice == "8") {
      if (serverMode != "authority") {
        std::cout << "invite key management is authority-only. Start server in authority mode on your admin machine.\n";
        continue;
      }
      std::string key = trim(readLine("Invite key", ""));
      std::string issuer = normalizeEndpointURL(readLine("Issuer URL (optional)", ""), 8082);
      if (key.empty()) {
        std::cout << "invite key is required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " invite-check"
          << " --key " << shellEscape(key);
      if (!issuer.empty()) {
        cmd << " --issuer-url " << shellEscape(issuer);
      }
      appendOptionalAdminAuthArgs(cmd);
      runCommand(cmd.str());
      continue;
    }
    if (choice == "9") {
      if (serverMode != "authority") {
        std::cout << "invite key management is authority-only. Start server in authority mode on your admin machine.\n";
        continue;
      }
      std::string key = trim(readLine("Invite key to disable", ""));
      std::string issuer = normalizeEndpointURL(readLine("Issuer URL (optional)", ""), 8082);
      if (key.empty()) {
        std::cout << "invite key is required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " invite-disable"
          << " --key " << shellEscape(key);
      if (!issuer.empty()) {
        cmd << " --issuer-url " << shellEscape(issuer);
      }
      appendOptionalAdminAuthArgs(cmd);
      runCommand(cmd.str());
      continue;
    }
    if (choice == "10") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "12";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "12");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string minSources = readLine("Minimum directory sources", "2");
      std::string minOperators = readLine("Minimum operators per directory", "2");
      std::string federationTimeout = readLine("Federation wait timeout sec", "90");
      std::string timeoutSec = readLine("Client validation timeout sec", "50");
      std::string subject = trim(readLine("Client subject key (optional)", ""));
      bool betaProfile = parseYesNo(readLine("Enable beta profile defaults? (Y/n)", "y"), true);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      PathProfile pathProfile = choosePathProfile("Path profile (1=Fast, 2=Balanced, 3=Privacy)", "2");
      bool distinct = pathProfile.distinctOperators;
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
        pathProfile.distinctOperators = true;
      }

      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }

      std::ostringstream cmd;
      cmd << shellEscape(script) << " three-machine-validate"
          << " --min-sources " << shellEscape(minSources)
          << " --min-operators " << shellEscape(minOperators)
          << " --federation-timeout-sec " << shellEscape(federationTimeout)
          << " --timeout-sec " << shellEscape(timeoutSec)
          << " --beta-profile " << (betaProfile ? "1" : "0")
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --distinct-operators " << (distinct ? "1" : "0");
      cmd << " --distinct-countries " << (pathProfile.distinctCountries ? "1" : "0")
          << " --locality-soft-bias " << (pathProfile.localitySoftBias ? "1" : "0")
          << " --country-bias " << shellEscape(pathProfile.countryBias)
          << " --region-bias " << shellEscape(pathProfile.regionBias)
          << " --region-prefix-bias " << shellEscape(pathProfile.regionPrefixBias);
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --discovery-wait-sec " << shellEscape(discoveryWait);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "11") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "12";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "12");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string rounds = readLine("Soak rounds", "10");
      std::string pauseSec = readLine("Pause between rounds sec", "5");
      std::string minSources = readLine("Minimum directory sources", "2");
      std::string minOperators = readLine("Minimum operators per directory", "2");
      std::string federationTimeout = readLine("Federation wait timeout sec", "90");
      std::string timeoutSec = readLine("Client validation timeout sec", "50");
      std::string subject = trim(readLine("Client subject key (optional)", ""));
      bool betaProfile = parseYesNo(readLine("Enable beta profile defaults? (Y/n)", "y"), true);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      PathProfile pathProfile = choosePathProfile("Path profile (1=Fast, 2=Balanced, 3=Privacy)", "2");
      bool distinct = pathProfile.distinctOperators;
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
        pathProfile.distinctOperators = true;
      }
      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " three-machine-soak"
          << " --rounds " << shellEscape(rounds)
          << " --pause-sec " << shellEscape(pauseSec)
          << " --min-sources " << shellEscape(minSources)
          << " --min-operators " << shellEscape(minOperators)
          << " --federation-timeout-sec " << shellEscape(federationTimeout)
          << " --timeout-sec " << shellEscape(timeoutSec)
          << " --beta-profile " << (betaProfile ? "1" : "0")
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --distinct-operators " << (distinct ? "1" : "0");
      cmd << " --distinct-countries " << (pathProfile.distinctCountries ? "1" : "0")
          << " --locality-soft-bias " << (pathProfile.localitySoftBias ? "1" : "0")
          << " --country-bias " << shellEscape(pathProfile.countryBias)
          << " --region-bias " << shellEscape(pathProfile.regionBias)
          << " --region-prefix-bias " << shellEscape(pathProfile.regionPrefixBias);
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --discovery-wait-sec " << shellEscape(discoveryWait);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "12") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "12";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "12");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string rounds = readLine("Soak rounds", "10");
      std::string pauseSec = readLine("Pause between rounds sec", "5");
      std::string subject = trim(readLine("Client subject key (optional)", ""));
      bool betaProfile = parseYesNo(readLine("Enable beta profile defaults? (Y/n)", "y"), true);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      PathProfile pathProfile = choosePathProfile("Path profile (1=Fast, 2=Balanced, 3=Privacy)", "2");
      bool distinct = pathProfile.distinctOperators;
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
        pathProfile.distinctOperators = true;
      }
      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " pilot-runbook"
          << " --rounds " << shellEscape(rounds)
          << " --pause-sec " << shellEscape(pauseSec)
          << " --beta-profile " << (betaProfile ? "1" : "0")
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --distinct-operators " << (distinct ? "1" : "0");
      cmd << " --distinct-countries " << (pathProfile.distinctCountries ? "1" : "0")
          << " --locality-soft-bias " << (pathProfile.localitySoftBias ? "1" : "0")
          << " --country-bias " << shellEscape(pathProfile.countryBias)
          << " --region-bias " << shellEscape(pathProfile.regionBias)
          << " --region-prefix-bias " << shellEscape(pathProfile.regionPrefixBias);
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --discovery-wait-sec " << shellEscape(discoveryWait);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "13") {
      runTestsInteractive(root, script, hosts);
      continue;
    }
    if (choice == "14") {
      bool autoDiscoverHosts = parseYesNo(readLine("Auto-discover machine A/B hosts from one bootstrap directory? (Y/n)", "y"), true);
      if (autoDiscoverHosts) {
        std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
        std::string bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        std::string waitSec = readLine("Discovery wait sec", "20");
        if (bootstrapDir.empty()) {
          std::cout << "bootstrap directory URL is required\n";
          continue;
        }
        std::ostringstream cmd;
        cmd << shellEscape(script) << " discover-hosts"
            << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --wait-sec " << shellEscape(waitSec)
            << " --write-config 1";
        runCommand(cmd.str());
        hosts = loadABHosts(root);
      } else {
        configureABHostsInteractive(root, hosts, true);
      }
      continue;
    }
    if (choice == "15") {
      showThreeMachineGuide();
      continue;
    }
    if (choice == "16") {
      std::string outDir = readLine("TLS output dir", "deploy/tls");
      std::string publicHost = normalizePublicHostInput(readLine("Primary public host/IP (optional)", ""));
      std::string rotateLeaf = parseYesNo(readLine("Rotate leaf certs? (y/N)", "n"), false) ? "1" : "0";
      std::string rotateCA = parseYesNo(readLine("Rotate CA cert/key? (y/N)", "n"), false) ? "1" : "0";
      std::ostringstream cmd;
      cmd << shellEscape(script) << " bootstrap-mtls"
          << " --out-dir " << shellEscape(outDir)
          << " --rotate-leaf " << shellEscape(rotateLeaf)
          << " --rotate-ca " << shellEscape(rotateCA);
      if (!publicHost.empty()) {
        cmd << " --public-host " << shellEscape(publicHost);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "17") {
      std::string daysMin = readLine("Minimum cert validity days", "14");
      bool checkLive = parseYesNo(readLine("Check live endpoints now? (y/N)", "n"), false);
      std::string timeoutSec = readLine("Live endpoint timeout sec", "12");
      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-preflight"
          << " --days-min " << shellEscape(daysMin)
          << " --check-live " << (checkLive ? "1" : "0")
          << " --timeout-sec " << shellEscape(timeoutSec);
      runCommand(cmd.str());
      continue;
    }
    if (choice == "18") {
      runCommand(shellEscape(script) + " admin-signing-status");
      continue;
    }
    if (choice == "19") {
      bool restartIssuer = parseYesNo(readLine("Restart issuer after rotation? (Y/n)", "y"), true);
      std::string keyHistory = readLine("Signing key history size", "3");
      std::ostringstream cmd;
      cmd << shellEscape(script) << " admin-signing-rotate"
          << " --restart-issuer " << (restartIssuer ? "1" : "0")
          << " --key-history " << shellEscape(keyHistory);
      runCommand(cmd.str());
      continue;
    }
    if (choice == "20") {
      runCommand(shellEscape(script) + " wg-only-check");
      continue;
    }
    if (choice == "21") {
      bool matrix = parseYesNo(readLine("Run matrix profile set? (Y/n)", "y"), true);
      bool strictBeta = parseYesNo(readLine("Use strict beta profile when non-matrix? (Y/n)", "y"), true);
      std::string timeoutSec = readLine("Timeout sec for non-matrix run", "150");
      std::ostringstream cmd;
      cmd << shellEscape(script) << " wg-only-local-test"
          << " --matrix " << (matrix ? "1" : "0")
          << " --strict-beta " << (strictBeta ? "1" : "0")
          << " --timeout-sec " << shellEscape(timeoutSec);
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "22") {
      bool strictBeta = parseYesNo(readLine("Strict beta profile? (Y/n)", "y"), true);
      std::string basePort = trim(readLine("Base port (blank=default 19080)", ""));
      std::ostringstream cmd;
      cmd << shellEscape(script) << " wg-only-stack-up"
          << " --strict-beta " << (strictBeta ? "1" : "0")
          << " --detach 1";
      if (!basePort.empty()) {
        cmd << " --base-port " << shellEscape(basePort);
      }
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "23") {
      runCommand(shellEscape(script) + " wg-only-stack-status");
      continue;
    }
    if (choice == "24") {
      bool forceIfaceCleanup = parseYesNo(readLine("Force interface cleanup? (y/N)", "n"), false);
      std::ostringstream cmd;
      cmd << shellEscape(script) << " wg-only-stack-down"
          << " --force-iface-cleanup " << (forceIfaceCleanup ? "1" : "0");
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "25") {
      bool strictBeta = parseYesNo(readLine("Strict beta profile? (Y/n)", "y"), true);
      std::string timeoutSec = readLine("Client validation timeout sec", "80");
      std::string minSelection = readLine("Minimum selection lines", "8");
      std::string basePort = trim(readLine("Base port (blank=default 19080)", ""));
      std::ostringstream cmd;
      cmd << shellEscape(script) << " wg-only-stack-selftest"
          << " --strict-beta " << (strictBeta ? "1" : "0")
          << " --timeout-sec " << shellEscape(timeoutSec)
          << " --min-selection-lines " << shellEscape(minSelection)
          << " --force-iface-reset 1"
          << " --cleanup-ifaces 1";
      if (!basePort.empty()) {
        cmd << " --base-port " << shellEscape(basePort);
      }
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "26") {
      bool restart = parseYesNo(readLine("Restart server services after rotating secrets? (Y/n)", "y"), true);
      bool rotateIssuerAdmin = parseYesNo(readLine("Rotate issuer admin token too (authority mode)? (Y/n)", "y"), true);
      bool showSecrets = parseYesNo(readLine("Show generated secrets in console? (y/N)", "n"), false);
      std::ostringstream cmd;
      cmd << shellEscape(script) << " rotate-server-secrets"
          << " --restart " << (restart ? "1" : "0")
          << " --rotate-issuer-admin " << (rotateIssuerAdmin ? "1" : "0")
          << " --show-secrets " << (showSecrets ? "1" : "0");
      runCommand(cmd.str());
      continue;
    }
    if (choice == "27") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "20";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "20");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string subject = trim(readLine("Client subject key (optional)", ""));
      std::string clientTimeout = readLine("Client timeout sec", "120");
      std::string wgSessionSec = readLine("WG session sec", "45");
      bool strictDistinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", "y"), true);
      bool skipControl = parseYesNo(readLine("Skip control-plane precheck? (y/N)", "n"), false);
      std::string mtlsCA = readLine("mTLS CA file", "deploy/tls/ca.crt");
      std::string mtlsCert = readLine("mTLS client cert file", "deploy/tls/client.crt");
      std::string mtlsKey = readLine("mTLS client key file", "deploy/tls/client.key");
      std::string report = readLine("Report file path (optional)", "");
      std::string summaryJson = readLine("WG validate summary JSON path (optional)", "");
      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-wg-validate"
          << " --client-timeout-sec " << shellEscape(clientTimeout)
          << " --wg-session-sec " << shellEscape(wgSessionSec)
          << " --strict-distinct " << (strictDistinct ? "1" : "0")
          << " --skip-control-plane-check " << (skipControl ? "1" : "0")
          << " --mtls-ca-file " << shellEscape(mtlsCA)
          << " --mtls-client-cert-file " << shellEscape(mtlsCert)
          << " --mtls-client-key-file " << shellEscape(mtlsKey);
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --discovery-wait-sec " << shellEscape(discoveryWait);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "28") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "20";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "20");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string subject = trim(readLine("Client subject key (optional)", ""));
      std::string rounds = readLine("Soak rounds", "10");
      std::string pauseSec = readLine("Pause between rounds sec", "8");
      std::string maxConsecutiveFailures = readLine("Max consecutive failures before abort", "2");
      std::string faultEvery = readLine("Inject fault every N rounds (0=off)", "0");
      std::string faultCommand = readLine("Fault command (optional)", "");
      bool continueOnFail = parseYesNo(readLine("Continue when a round fails? (y/N)", "n"), false);
      bool strictDistinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", "y"), true);
      bool skipControl = parseYesNo(readLine("Skip control-plane precheck in each round? (Y/n)", "y"), true);
      std::string mtlsCA = readLine("mTLS CA file", "deploy/tls/ca.crt");
      std::string mtlsCert = readLine("mTLS client cert file", "deploy/tls/client.crt");
      std::string mtlsKey = readLine("mTLS client key file", "deploy/tls/client.key");
      std::string report = readLine("Report file path (optional)", "");
      std::string wgSoakSummaryJson = readLine("WG soak summary JSON path (optional)", "");
      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-wg-soak"
          << " --rounds " << shellEscape(rounds)
          << " --pause-sec " << shellEscape(pauseSec)
          << " --max-consecutive-failures " << shellEscape(maxConsecutiveFailures)
          << " --fault-every " << shellEscape(faultEvery)
          << " --continue-on-fail " << (continueOnFail ? "1" : "0")
          << " --strict-distinct " << (strictDistinct ? "1" : "0")
          << " --skip-control-plane-check " << (skipControl ? "1" : "0")
          << " --mtls-ca-file " << shellEscape(mtlsCA)
          << " --mtls-client-cert-file " << shellEscape(mtlsCert)
          << " --mtls-client-key-file " << shellEscape(mtlsKey);
      if (!faultCommand.empty()) {
        cmd << " --fault-command " << shellEscape(faultCommand);
      }
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir)
            << " --discovery-wait-sec " << shellEscape(discoveryWait);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      if (!wgSoakSummaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(wgSoakSummaryJson);
      }
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "29") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "20";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "20");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      std::string subject = trim(readLine("Client subject key (optional)", ""));
      std::string controlSoakRounds = readLine("Control soak rounds", "10");
      std::string controlSoakPause = readLine("Control soak pause sec", "5");
      std::string wgSoakRounds = readLine("WG soak rounds", "10");
      std::string wgSoakPause = readLine("WG soak pause sec", "8");
      std::string wgMaxConsecutiveFailures = readLine("WG max consecutive failures before abort", "2");
      std::string wgSloProfile = trim(readLine("WG SLO profile (off/recommended/strict)", "recommended"));
      std::string controlTimeout = readLine("Control timeout sec", "50");
      std::string wgClientTimeout = readLine("WG client timeout sec", "120");
      std::string wgSessionSec = readLine("WG session sec", "45");
      std::string controlFaultEvery = readLine("Inject CONTROL fault every N rounds (0=off)", "0");
      std::string controlFaultCommand = readLine("Control fault command (optional)", "");
      bool controlContinueOnFail = parseYesNo(readLine("Continue when control soak round fails? (y/N)", "n"), false);
      std::string wgFaultEvery = readLine("Inject WG fault every N rounds (0=off)", "0");
      std::string wgFaultCommand = readLine("WG fault command (optional)", "");
      bool wgContinueOnFail = parseYesNo(readLine("Continue when WG soak round fails? (y/N)", "n"), false);
      std::string wgMaxRoundDuration = trim(readLine("WG max round duration sec override (blank=profile/default)", ""));
      std::string wgMaxRecovery = trim(readLine("WG max recovery sec override (blank=profile/default)", ""));
      std::string wgMaxFailureClass = trim(readLine("WG max failure class budget CLASS=N override (blank=profile/default)", ""));
      std::string wgMinSelectionLines = trim(readLine("WG min selection lines override (blank=profile/default)", ""));
      std::string wgMinEntryOperators = trim(readLine("WG min entry operators override (blank=profile/default)", ""));
      std::string wgMinExitOperators = trim(readLine("WG min exit operators override (blank=profile/default)", ""));
      std::string wgMinCrossOperatorPairs = trim(readLine("WG min cross-operator pairs override (blank=profile/default)", ""));
      std::string wgDisallowUnknownRaw = trim(readLine("Disallow unknown WG failure class override (blank=profile/default, y/n)", ""));
      bool hasWGDisallowUnknownOverride = !wgDisallowUnknownRaw.empty();
      bool wgDisallowUnknownClass = parseYesNo(wgDisallowUnknownRaw, true);
      bool strictDistinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", "y"), true);
      bool skipControlSoak = parseYesNo(readLine("Skip control-plane soak step? (y/N)", "n"), false);
      bool skipWG = parseYesNo(readLine("Skip real-WG steps (control only)? (y/N)", "n"), false);
      bool skipWGSoak = parseYesNo(readLine("Skip real-WG soak step? (y/N)", "n"), false);
      std::string mtlsCA = readLine("mTLS CA file", "deploy/tls/ca.crt");
      std::string mtlsCert = readLine("mTLS client cert file", "deploy/tls/client.crt");
      std::string mtlsKey = readLine("mTLS client key file", "deploy/tls/client.key");
      std::string bundleDir = readLine("Bundle directory (optional)", "");
      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " three-machine-prod-bundle"
          << " --discovery-wait-sec " << shellEscape(discoveryWait)
          << " --control-soak-rounds " << shellEscape(controlSoakRounds)
          << " --control-soak-pause-sec " << shellEscape(controlSoakPause)
          << " --wg-soak-rounds " << shellEscape(wgSoakRounds)
          << " --wg-soak-pause-sec " << shellEscape(wgSoakPause)
          << " --wg-slo-profile " << shellEscape(wgSloProfile)
          << " --wg-max-consecutive-failures " << shellEscape(wgMaxConsecutiveFailures)
          << " --control-timeout-sec " << shellEscape(controlTimeout)
          << " --wg-client-timeout-sec " << shellEscape(wgClientTimeout)
          << " --wg-session-sec " << shellEscape(wgSessionSec)
          << " --control-fault-every " << shellEscape(controlFaultEvery)
          << " --control-continue-on-fail " << (controlContinueOnFail ? "1" : "0")
          << " --wg-fault-every " << shellEscape(wgFaultEvery)
          << " --wg-continue-on-fail " << (wgContinueOnFail ? "1" : "0")
          << " --strict-distinct " << (strictDistinct ? "1" : "0")
          << " --skip-control-soak " << (skipControlSoak ? "1" : "0")
          << " --skip-wg " << (skipWG ? "1" : "0")
          << " --skip-wg-soak " << (skipWGSoak ? "1" : "0")
          << " --mtls-ca-file " << shellEscape(mtlsCA)
          << " --mtls-client-cert-file " << shellEscape(mtlsCert)
          << " --mtls-client-key-file " << shellEscape(mtlsKey);
      if (!controlFaultCommand.empty()) {
        cmd << " --control-fault-command " << shellEscape(controlFaultCommand);
      }
      if (!wgFaultCommand.empty()) {
        cmd << " --wg-fault-command " << shellEscape(wgFaultCommand);
      }
      if (!wgMaxFailureClass.empty()) {
        cmd << " --wg-max-failure-class " << shellEscape(wgMaxFailureClass);
      }
      if (!wgMinSelectionLines.empty()) {
        cmd << " --wg-min-selection-lines " << shellEscape(wgMinSelectionLines);
      }
      if (!wgMinEntryOperators.empty()) {
        cmd << " --wg-min-entry-operators " << shellEscape(wgMinEntryOperators);
      }
      if (!wgMinExitOperators.empty()) {
        cmd << " --wg-min-exit-operators " << shellEscape(wgMinExitOperators);
      }
      if (!wgMinCrossOperatorPairs.empty()) {
        cmd << " --wg-min-cross-operator-pairs " << shellEscape(wgMinCrossOperatorPairs);
      }
      if (!wgMaxRoundDuration.empty()) {
        cmd << " --wg-max-round-duration-sec " << shellEscape(wgMaxRoundDuration);
      }
      if (!wgMaxRecovery.empty()) {
        cmd << " --wg-max-recovery-sec " << shellEscape(wgMaxRecovery);
      }
      if (hasWGDisallowUnknownOverride) {
        cmd << " --wg-disallow-unknown-failure-class " << (wgDisallowUnknownClass ? "1" : "0");
      }
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }

      std::ostringstream preflightCmd;
      preflightCmd << shellEscape(script) << " client-vpn-preflight"
                   << " --discovery-wait-sec " << shellEscape(discoveryWait)
                   << " --prod-profile 1"
                   << " --operator-floor-check 1"
                   << " --issuer-quorum-check 1"
                   << " --issuer-min-operators 2"
                   << " --timeout-sec 12"
                   << " --require-root 1"
                   << " --mtls-ca-file " << shellEscape("deploy/tls/ca.crt")
                   << " --mtls-client-cert-file " << shellEscape("deploy/tls/client.crt")
                   << " --mtls-client-key-file " << shellEscape("deploy/tls/client.key");
      if (autoDiscover) {
        preflightCmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
      } else {
        std::string directoryUrls = dirA + "," + dirB;
        preflightCmd << " --directory-urls " << shellEscape(directoryUrls)
                     << " --issuer-url " << shellEscape(issuer)
                     << " --entry-url " << shellEscape(entry)
                     << " --exit-url " << shellEscape(exitUrl);
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!bundleDir.empty()) {
        cmd << " --bundle-dir " << shellEscape(bundleDir);
      }
      if (!skipWG && !isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "30") {
      runCommand(shellEscape(script) + " three-machine-reminder");
      continue;
    }
    if (choice == "31") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "20";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "20");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }
      bool prodProfile = parseYesNo(readLine("Use PROD profile? (y/N)", "n"), false);
      bool operatorFloorCheck = parseYesNo(
          readLine("Enforce operator floor check (>=2 entry/exit operators)? (Y/n)", prodProfile ? "y" : "n"),
          prodProfile);
      bool issuerQuorumCheck = parseYesNo(
          readLine("Enforce issuer quorum check (>=2 distinct issuer IDs)? (Y/n)", prodProfile ? "y" : "n"),
          prodProfile);
      std::string issuerMinOperators = readLine("Issuer min operators (when quorum check enabled)", "2");
      std::string issuerURLs = trim(readLine("Extra issuer URLs CSV (optional; auto-derived if blank)", ""));
      std::string iface = trim(readLine("VPN interface name", "wgvpn0"));
      std::string timeoutSec = readLine("Endpoint/preflight timeout sec", "12");
      std::ostringstream cmd;
      cmd << shellEscape(script) << " client-vpn-preflight"
          << " --discovery-wait-sec " << shellEscape(discoveryWait)
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --operator-floor-check " << (operatorFloorCheck ? "1" : "0")
          << " --issuer-quorum-check " << (issuerQuorumCheck ? "1" : "0")
          << " --issuer-min-operators " << shellEscape(issuerMinOperators)
          << " --interface " << shellEscape(iface)
          << " --timeout-sec " << shellEscape(timeoutSec);
      if (autoDiscover) {
        if (bootstrapDir.empty()) {
          std::cout << "bootstrap directory URL is required\n";
          continue;
        }
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
      } else {
        if (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty()) {
          std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
          continue;
        }
        cmd << " --directory-urls " << shellEscape(dirA + "," + dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!issuerURLs.empty()) {
        cmd << " --issuer-urls " << shellEscape(issuerURLs);
      }
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "32") {
      runCommand(shellEscape(script) + " client-vpn-status");
      continue;
    }
    if (choice == "33") {
      bool forceIface = parseYesNo(readLine("Force interface cleanup? (Y/n)", "y"), true);
      bool keepKey = parseYesNo(readLine("Keep client key file? (Y/n)", "y"), true);
      std::ostringstream cmd;
      cmd << shellEscape(script) << " client-vpn-down"
          << " --force-iface-cleanup " << (forceIface ? "1" : "0")
          << " --keep-key " << (keepKey ? "1" : "0");
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "34") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "20";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
        discoveryWait = readLine("Bootstrap discovery wait sec", "20");
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL", endpointFromHost(hosts.aHost, 8084)), 8084);
      }

      bool useAnonCred = parseYesNo(readLine("Use anonymous credential token instead of invite subject? (y/N)", "n"), false);
      std::string subject = "";
      std::string anonCred = "";
      if (useAnonCred) {
        anonCred = trim(readLine("Anonymous credential token", ""));
      } else {
        subject = trim(readLine("Invite subject key", ""));
      }

      std::string minSources = readLine("Minimum directory sources", "2");
      std::string minOperators = readLine("Minimum operators", "2");
      bool betaProfile = parseYesNo(readLine("Enable beta profile defaults? (Y/n)", "y"), true);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      PathProfile pathProfile = choosePathProfile("Path profile (1=Fast, 2=Balanced, 3=Privacy)", "2");
      bool distinct = pathProfile.distinctOperators;
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
        pathProfile.distinctOperators = true;
      }
      bool operatorFloorCheck = parseYesNo(
          readLine("Enforce operator floor check (>=2 entry/exit operators)? (Y/n)", prodProfile ? "y" : "n"),
          prodProfile);
      bool issuerQuorumCheck = parseYesNo(
          readLine("Enforce issuer quorum check (>=2 distinct issuer IDs)? (Y/n)", prodProfile ? "y" : "n"),
          prodProfile);
      std::string issuerMinOperators = readLine("Issuer min operators (when quorum check enabled)", "2");
      std::string issuerURLs = trim(readLine("Extra issuer URLs CSV (optional; auto-derived if blank)", ""));

      std::string iface = trim(readLine("VPN interface name", "wgvpn0"));
      std::string proxyAddr = trim(readLine("WG proxy address", "127.0.0.1:57960"));
      std::string privateKeyFile = trim(readLine("Client private key file (optional)", ""));
      std::string allowedIPs = trim(readLine("Allowed IPs", "0.0.0.0/0"));
      bool installRoute = parseYesNo(readLine("Install default route through VPN? (y/N)", "n"), false);
      std::string startupSyncTimeout = readLine("Startup sync timeout sec", "25");
      std::string readyTimeout = readLine("Ready timeout sec", "35");
      bool forceRestart = parseYesNo(readLine("Force restart if VPN already running? (Y/n)", "y"), true);
      bool foreground = parseYesNo(readLine("Run in foreground? (y/N)", "n"), false);
      std::string mtlsCA = trim(readLine("mTLS CA file (optional)", ""));
      std::string mtlsCert = trim(readLine("mTLS client cert file (optional)", ""));
      std::string mtlsKey = trim(readLine("mTLS client key file (optional)", ""));
      std::string logFile = trim(readLine("Client log file (optional)", ""));
      bool runPreflight = parseYesNo(readLine("Run client-vpn-preflight first? (Y/n)", "y"), true);
      std::string preflightTimeout = readLine("Preflight timeout sec", "12");

      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      if (useAnonCred && anonCred.empty()) {
        std::cout << "anonymous credential token is required in anon mode\n";
        continue;
      }
      if (!useAnonCred && subject.empty()) {
        std::cout << "invite subject key is required\n";
        continue;
      }
      if (iface.empty() || proxyAddr.empty() || allowedIPs.empty()) {
        std::cout << "interface, proxy address and allowed IPs are required\n";
        continue;
      }

      if (runPreflight) {
        std::ostringstream preflightCmd;
        preflightCmd << shellEscape(script) << " client-vpn-preflight"
                     << " --discovery-wait-sec " << shellEscape(discoveryWait)
                     << " --prod-profile " << (prodProfile ? "1" : "0")
                     << " --operator-floor-check " << (operatorFloorCheck ? "1" : "0")
                     << " --issuer-quorum-check " << (issuerQuorumCheck ? "1" : "0")
                     << " --issuer-min-operators " << shellEscape(issuerMinOperators)
                     << " --interface " << shellEscape(iface)
                     << " --timeout-sec " << shellEscape(preflightTimeout);
        if (autoDiscover) {
          preflightCmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
        } else {
          preflightCmd << " --directory-urls " << shellEscape(dirA + "," + dirB)
                       << " --issuer-url " << shellEscape(issuer)
                       << " --entry-url " << shellEscape(entry)
                       << " --exit-url " << shellEscape(exitUrl);
        }
        if (!issuerURLs.empty()) {
          preflightCmd << " --issuer-urls " << shellEscape(issuerURLs);
        }
        if (!mtlsCA.empty()) {
          preflightCmd << " --mtls-ca-file " << shellEscape(mtlsCA);
        }
        if (!mtlsCert.empty()) {
          preflightCmd << " --mtls-client-cert-file " << shellEscape(mtlsCert);
        }
        if (!mtlsKey.empty()) {
          preflightCmd << " --mtls-client-key-file " << shellEscape(mtlsKey);
        }
        int preflightRc = 0;
        if (!isRootUser()) {
          bool useSudoPreflight = parseYesNo(readLine("Run preflight with sudo? (Y/n)", "y"), true);
          if (useSudoPreflight) {
            preflightRc = runCommand("sudo " + preflightCmd.str());
          } else {
            preflightRc = runCommand(preflightCmd.str());
          }
        } else {
          preflightRc = runCommand(preflightCmd.str());
        }
        if (preflightRc != 0) {
          std::cout << "preflight failed; not starting client-vpn-up\n";
          continue;
        }
      }

      std::ostringstream cmd;
      cmd << shellEscape(script) << " client-vpn-up"
          << " --discovery-wait-sec " << shellEscape(discoveryWait)
          << " --min-sources " << shellEscape(minSources)
          << " --min-operators " << shellEscape(minOperators)
          << " --distinct-operators " << (distinct ? "1" : "0")
          << " --beta-profile " << (betaProfile ? "1" : "0")
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --operator-floor-check " << (operatorFloorCheck ? "1" : "0")
          << " --issuer-quorum-check " << (issuerQuorumCheck ? "1" : "0")
          << " --issuer-min-operators " << shellEscape(issuerMinOperators)
          << " --interface " << shellEscape(iface)
          << " --proxy-addr " << shellEscape(proxyAddr)
          << " --allowed-ips " << shellEscape(allowedIPs)
          << " --install-route " << (installRoute ? "1" : "0")
          << " --startup-sync-timeout-sec " << shellEscape(startupSyncTimeout)
          << " --ready-timeout-sec " << shellEscape(readyTimeout)
          << " --force-restart " << (forceRestart ? "1" : "0")
          << " --foreground " << (foreground ? "1" : "0");
      cmd << " --distinct-countries " << (pathProfile.distinctCountries ? "1" : "0")
          << " --locality-soft-bias " << (pathProfile.localitySoftBias ? "1" : "0")
          << " --country-bias " << shellEscape(pathProfile.countryBias)
          << " --region-bias " << shellEscape(pathProfile.regionBias)
          << " --region-prefix-bias " << shellEscape(pathProfile.regionPrefixBias);
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
      } else {
        cmd << " --directory-urls " << shellEscape(dirA + "," + dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!issuerURLs.empty()) {
        cmd << " --issuer-urls " << shellEscape(issuerURLs);
      }
      if (useAnonCred) {
        cmd << " --anon-cred " << shellEscape(anonCred);
      } else {
        cmd << " --subject " << shellEscape(subject);
      }
      if (!privateKeyFile.empty()) {
        cmd << " --private-key-file " << shellEscape(privateKeyFile);
      }
      if (!mtlsCA.empty()) {
        cmd << " --mtls-ca-file " << shellEscape(mtlsCA);
      }
      if (!mtlsCert.empty()) {
        cmd << " --mtls-client-cert-file " << shellEscape(mtlsCert);
      }
      if (!mtlsKey.empty()) {
        cmd << " --mtls-client-key-file " << shellEscape(mtlsKey);
      }
      if (!logFile.empty()) {
        cmd << " --log-file " << shellEscape(logFile);
      }

      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run client-vpn-up with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "35") {
      std::string modeDefault = loadServerMode(root);
      if (modeDefault != "authority" && modeDefault != "provider") {
        modeDefault = "provider";
      }
      std::string modeInput = trim(readLine("Mode (authority/provider)", modeDefault));
      std::string mode = (modeInput == "authority") ? "authority" : "provider";
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string peerDirs;
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
      } else {
        peerDirs = trim(readLine("Peer directory URLs CSV", ""));
      }
      std::string authorityDir = "";
      std::string authorityIssuer = "";
      if (mode == "provider") {
        std::string authorityDirDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : bootstrapDefault;
        authorityDir = normalizeEndpointURL(readLine("Authority directory URL", authorityDirDefault), 8081);
        std::string authorityIssuerDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8082) : "";
        authorityIssuer = normalizeEndpointURL(readLine("Authority issuer URL", authorityIssuerDefault), 8082);
      }
      std::string publicHost = normalizePublicHostInput(readLine("Public host/IP for this server (optional)", ""));
      std::string operatorId = trim(readLine("Operator ID override (optional)", ""));
      std::string issuerId = "";
      if (mode == "authority") {
        issuerId = trim(readLine("Issuer ID override (optional)", ""));
      }
      bool betaProfile = parseYesNo(readLine("Enable beta profile defaults? (Y/n)", "y"), true);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile? (y/N)", "n"), false);
      if (prodProfile) {
        betaProfile = true;
      }
      std::string strictMode = trim(readLine("Peer identity strict mode (auto/1/0)", "auto"));
      std::string minPeerOperators = readLine("Min distinct peer operators", betaProfile ? "1" : "0");
      std::string timeoutSec = readLine("HTTP timeout sec", "8");

      std::ostringstream cmd;
      cmd << shellEscape(script) << " server-preflight"
          << " --mode " << shellEscape(mode)
          << " --beta-profile " << (betaProfile ? "1" : "0")
          << " --prod-profile " << (prodProfile ? "1" : "0")
          << " --peer-identity-strict " << shellEscape(strictMode)
          << " --min-peer-operators " << shellEscape(minPeerOperators)
          << " --timeout-sec " << shellEscape(timeoutSec);
      if (!publicHost.empty()) {
        cmd << " --public-host " << shellEscape(publicHost);
      }
      if (autoDiscover) {
        if (bootstrapDir.empty()) {
          std::cout << "bootstrap directory URL is required\n";
          continue;
        }
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
      } else if (!peerDirs.empty()) {
        cmd << " --peer-directories " << shellEscape(peerDirs);
      }
      if (!operatorId.empty()) {
        cmd << " --operator-id " << shellEscape(operatorId);
      }
      if (mode == "authority" && !issuerId.empty()) {
        cmd << " --issuer-id " << shellEscape(issuerId);
      }
      if (mode == "provider") {
        if (authorityDir.empty() || authorityIssuer.empty()) {
          std::cout << "authority directory and authority issuer are required for provider mode\n";
          continue;
        }
        cmd << " --authority-directory " << shellEscape(authorityDir)
            << " --authority-issuer " << shellEscape(authorityIssuer);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "36") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "20";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }

      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }

      std::string subject = trim(readLine("Client subject key (optional)", ""));
      std::string bundleDir = trim(readLine("Bundle directory", ".easy-node-logs/prod_gate_bundle_quick"));
      std::string report = trim(readLine("Gate report file (optional)", ""));
      std::string runReportJson = bundleDir.empty() ? "" : (bundleDir + "/prod_bundle_run_report.json");

      std::ostringstream cmd;
      cmd << shellEscape(script) << " three-machine-prod-bundle"
          << " --preflight-check 1"
          << " --bundle-verify-check 1"
          << " --bundle-verify-show-details 0"
          << " --discovery-wait-sec " << shellEscape(discoveryWait)
          << " --min-sources 2"
          << " --min-operators 2"
          << " --federation-timeout-sec 90"
          << " --control-timeout-sec 50"
          << " --control-soak-rounds 12"
          << " --control-soak-pause-sec 6"
          << " --wg-client-timeout-sec 120"
          << " --wg-session-sec 45"
          << " --wg-soak-rounds 12"
          << " --wg-soak-pause-sec 10"
          << " --wg-slo-profile strict"
          << " --wg-max-consecutive-failures 1"
          << " --wg-max-round-duration-sec 90"
          << " --wg-max-recovery-sec 120"
          << " --wg-max-failure-class endpoint_connectivity=1"
          << " --wg-max-failure-class timeout=1"
          << " --wg-max-failure-class wg_dataplane_stall=0"
          << " --wg-max-failure-class strict_ingress_policy=0"
          << " --wg-max-failure-class diversity_threshold=0"
          << " --wg-disallow-unknown-failure-class 1"
          << " --wg-min-selection-lines 12"
          << " --wg-min-entry-operators 2"
          << " --wg-min-exit-operators 2"
          << " --wg-min-cross-operator-pairs 3"
          << " --strict-distinct 1"
          << " --skip-control-soak 0"
          << " --skip-wg 0"
          << " --skip-wg-soak 0"
          << " --signoff-check 1"
          << " --signoff-require-full-sequence 1"
          << " --signoff-require-wg-validate-ok 1"
          << " --signoff-require-wg-soak-ok 1"
          << " --signoff-require-wg-validate-udp-source 1"
          << " --signoff-require-wg-validate-strict-distinct 1"
          << " --signoff-require-wg-soak-diversity-pass 1"
          << " --signoff-min-wg-soak-selection-lines 12"
          << " --signoff-min-wg-soak-entry-operators 2"
          << " --signoff-min-wg-soak-exit-operators 2"
          << " --signoff-min-wg-soak-cross-operator-pairs 3"
          << " --signoff-max-wg-soak-failed-rounds 0"
          << " --signoff-show-json 0"
          << " --control-fault-every 0"
          << " --control-continue-on-fail 0"
          << " --wg-fault-every 0"
          << " --wg-continue-on-fail 0"
          << " --mtls-ca-file " << shellEscape("deploy/tls/ca.crt")
          << " --mtls-client-cert-file " << shellEscape("deploy/tls/client.crt")
          << " --mtls-client-key-file " << shellEscape("deploy/tls/client.key");
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!bundleDir.empty()) {
        cmd << " --bundle-dir " << shellEscape(bundleDir);
      }
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson)
            << " --run-report-print 1";
        std::cout << "run report json: " << runReportJson << "\n";
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "37") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      std::string discoveryWait = "12";
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }

      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }

      std::string subject = trim(readLine("Client subject key (optional)", ""));
      std::string bundleDir = trim(readLine("Bundle directory", ".easy-node-logs/prod_gate_bundle_smoke"));
      std::string report = trim(readLine("Gate report file (optional)", ""));
      std::string runReportJson = bundleDir.empty() ? "" : (bundleDir + "/prod_bundle_run_report.json");

      std::ostringstream cmd;
      cmd << shellEscape(script) << " three-machine-prod-bundle"
          << " --preflight-check 0"
          << " --bundle-verify-check 1"
          << " --bundle-verify-show-details 0"
          << " --discovery-wait-sec " << shellEscape(discoveryWait)
          << " --min-sources 2"
          << " --min-operators 2"
          << " --federation-timeout-sec 60"
          << " --control-timeout-sec 40"
          << " --control-soak-rounds 3"
          << " --control-soak-pause-sec 3"
          << " --wg-client-timeout-sec 90"
          << " --wg-session-sec 30"
          << " --wg-soak-rounds 4"
          << " --wg-soak-pause-sec 4"
          << " --wg-slo-profile recommended"
          << " --wg-max-consecutive-failures 1"
          << " --wg-max-failure-class strict_ingress_policy=0"
          << " --wg-disallow-unknown-failure-class 1"
          << " --wg-min-selection-lines 8"
          << " --wg-min-entry-operators 2"
          << " --wg-min-exit-operators 2"
          << " --wg-min-cross-operator-pairs 2"
          << " --strict-distinct 1"
          << " --skip-control-soak 0"
          << " --skip-wg 0"
          << " --skip-wg-soak 0"
          << " --signoff-check 0"
          << " --control-fault-every 0"
          << " --control-continue-on-fail 0"
          << " --wg-fault-every 0"
          << " --wg-continue-on-fail 0"
          << " --mtls-ca-file " << shellEscape("deploy/tls/ca.crt")
          << " --mtls-client-cert-file " << shellEscape("deploy/tls/client.crt")
          << " --mtls-client-key-file " << shellEscape("deploy/tls/client.key");
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!bundleDir.empty()) {
        cmd << " --bundle-dir " << shellEscape(bundleDir);
      }
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson)
            << " --run-report-print 1";
        std::cout << "run report json: " << runReportJson << "\n";
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      std::cout << "note: smoke profile is fast sanity validation; use option 36 for full strict closed-beta sign-off.\n";
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "38") {
      std::string bundleDir = trim(readLine("Bundle directory override (optional)", ""));
      std::string bundleTar = trim(readLine("Bundle tar path (optional)", ""));
      std::string runReportJsonDefault = bundleDir.empty() ? "" : (bundleDir + "/prod_bundle_run_report.json");
      if (runReportJsonDefault.empty()) {
        runReportJsonDefault = ".easy-node-logs/prod_gate_bundle_quick/prod_bundle_run_report.json";
      }
      std::string runReportJson = trim(readLine("Run report JSON path (recommended)", runReportJsonDefault));
      bool verifyIntegrity = parseYesNo(readLine("Verify bundle integrity (manifest + tar checksum)? (Y/n)", "y"), true);
      bool showIntegrityDetails = parseYesNo(readLine("Show per-file integrity details? (y/N)", "n"), false);
      std::string gateSummaryJson = trim(readLine("Gate summary JSON path (optional)", ""));
      bool requireFullSequence = parseYesNo(readLine("Require full sequence (all steps=ok)? (Y/n)", "y"), true);
      bool requireWGValidate = parseYesNo(readLine("Require WG validate status=ok? (Y/n)", "y"), true);
      bool requireWGSoak = parseYesNo(readLine("Require WG soak status=ok? (Y/n)", "y"), true);
      std::string maxWGSoakFailedRounds = readLine("Max WG soak failed rounds", "0");
      bool requireRunReportStages = parseYesNo(readLine("Require run-report stages (preflight + bundle + integrity + signoff) to be ok? (y/N)", "n"), false);
      bool requireIncidentSnapshotOnFail = parseYesNo(readLine("Require incident snapshot status=ok when run report is fail? (y/N)", "n"), false);
      bool requireIncidentSnapshotArtifacts = parseYesNo(readLine("Require incident snapshot artifacts when snapshot evidence is required? (y/N)", "n"), false);
      bool showJson = parseYesNo(readLine("Show summary JSON payload? (y/N)", "n"), false);

      if (verifyIntegrity) {
        std::ostringstream signoffCmd;
        signoffCmd << shellEscape(script) << " prod-gate-signoff"
                   << " --check-tar-sha256 1"
                   << " --check-manifest 1"
                   << " --show-integrity-details " << (showIntegrityDetails ? "1" : "0")
                   << " --require-full-sequence " << (requireFullSequence ? "1" : "0")
                   << " --require-wg-validate-ok " << (requireWGValidate ? "1" : "0")
                   << " --require-wg-soak-ok " << (requireWGSoak ? "1" : "0")
                   << " --require-preflight-ok " << (requireRunReportStages ? "1" : "0")
                   << " --require-bundle-ok " << (requireRunReportStages ? "1" : "0")
                   << " --require-integrity-ok " << (requireRunReportStages ? "1" : "0")
                   << " --require-signoff-ok " << (requireRunReportStages ? "1" : "0")
                   << " --require-incident-snapshot-on-fail " << (requireIncidentSnapshotOnFail ? "1" : "0")
                   << " --require-incident-snapshot-artifacts " << (requireIncidentSnapshotArtifacts ? "1" : "0")
                   << " --require-wg-validate-udp-source 1"
                   << " --require-wg-validate-strict-distinct 1"
                   << " --require-wg-soak-diversity-pass 1"
                   << " --min-wg-soak-selection-lines 12"
                   << " --min-wg-soak-entry-operators 2"
                   << " --min-wg-soak-exit-operators 2"
                   << " --min-wg-soak-cross-operator-pairs 2"
                   << " --max-wg-soak-failed-rounds " << shellEscape(maxWGSoakFailedRounds)
                   << " --show-json " << (showJson ? "1" : "0");
        if (!runReportJson.empty()) {
          signoffCmd << " --run-report-json " << shellEscape(runReportJson);
        }
        if (!bundleDir.empty()) {
          signoffCmd << " --bundle-dir " << shellEscape(bundleDir);
        }
        if (!bundleTar.empty()) {
          signoffCmd << " --bundle-tar " << shellEscape(bundleTar);
        }
        if (!gateSummaryJson.empty()) {
          signoffCmd << " --gate-summary-json " << shellEscape(gateSummaryJson);
        }
        runCommand(signoffCmd.str());
        continue;
      }

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-gate-check"
          << " --require-full-sequence " << (requireFullSequence ? "1" : "0")
          << " --require-wg-validate-ok " << (requireWGValidate ? "1" : "0")
          << " --require-wg-soak-ok " << (requireWGSoak ? "1" : "0")
          << " --require-preflight-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-bundle-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-integrity-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-signoff-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireIncidentSnapshotOnFail ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireIncidentSnapshotArtifacts ? "1" : "0")
          << " --require-wg-validate-udp-source 1"
          << " --require-wg-validate-strict-distinct 1"
          << " --require-wg-soak-diversity-pass 1"
          << " --min-wg-soak-selection-lines 12"
          << " --min-wg-soak-entry-operators 2"
          << " --min-wg-soak-exit-operators 2"
          << " --min-wg-soak-cross-operator-pairs 2"
          << " --max-wg-soak-failed-rounds " << shellEscape(maxWGSoakFailedRounds)
          << " --show-json " << (showJson ? "1" : "0");
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson);
      }
      if (!bundleDir.empty()) {
        cmd << " --bundle-dir " << shellEscape(bundleDir);
      }
      if (!gateSummaryJson.empty()) {
        cmd << " --gate-summary-json " << shellEscape(gateSummaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "39") {
      bool autoDiscover = parseYesNo(readLine("Use one bootstrap directory and auto-discover peers? (Y/n)", "y"), true);
      std::string bootstrapDefault = !hosts.aHost.empty() ? endpointFromHost(hosts.aHost, 8081) : (!hosts.bHost.empty() ? endpointFromHost(hosts.bHost, 8081) : "");
      std::string bootstrapDir;
      std::string dirA;
      std::string dirB;
      std::string issuer;
      std::string entry;
      std::string exitUrl;
      if (autoDiscover) {
        bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
      } else {
        configureABHostsInteractive(root, hosts, false);
        dirA = normalizeEndpointURL(readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081)), 8081);
        dirB = normalizeEndpointURL(readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081)), 8081);
        issuer = normalizeEndpointURL(readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082)), 8082);
        entry = normalizeEndpointURL(readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083)), 8083);
        exitUrl = normalizeEndpointURL(readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084)), 8084);
      }

      if (autoDiscover && bootstrapDir.empty()) {
        std::cout << "bootstrap directory URL is required\n";
        continue;
      }
      if (!autoDiscover && (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty())) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }

      std::string subject = trim(readLine("Client subject key (optional)", ""));
      std::string bundleDir = trim(readLine("Bundle directory", ".easy-node-logs/prod_pilot_bundle"));
      std::string runReportJson = bundleDir.empty() ? "" : (bundleDir + "/prod_bundle_run_report.json");
      std::string report = trim(readLine("Gate report file (optional)", ""));
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness first? (Y/n)", "y"), true);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-runbook";
      if (autoDiscover) {
        cmd << " --bootstrap-directory " << shellEscape(bootstrapDir);
      } else {
        cmd << " --directory-a " << shellEscape(dirA)
            << " --directory-b " << shellEscape(dirB)
            << " --issuer-url " << shellEscape(issuer)
            << " --entry-url " << shellEscape(entry)
            << " --exit-url " << shellEscape(exitUrl);
      }
      if (!subject.empty()) {
        cmd << " --subject " << shellEscape(subject);
      }
      if (!bundleDir.empty()) {
        cmd << " --bundle-dir " << shellEscape(bundleDir);
      }
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson)
            << " --run-report-print 1";
        std::cout << "run report json: " << runReportJson << "\n";
      }
      if (!report.empty()) {
        cmd << " --report-file " << shellEscape(report);
      }
      if (runPreRealHostReadiness) {
        cmd << " --pre-real-host-readiness 1";
      }
      std::cout << "note: prod-pilot-runbook uses strict fail-closed defaults and auto-generates SLO dashboard artifacts; pass extra flags in shell for advanced overrides.\n";
      if (!isRootUser()) {
        bool useSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);
        if (useSudo) {
          runCommand("sudo " + cmd.str());
        } else {
          runCommand(cmd.str());
        }
      } else {
        runCommand(cmd.str());
      }
      continue;
    }
    if (choice == "40") {
      std::string mode = trim(readLine("Snapshot mode (auto/authority/provider/client)", "auto"));
      if (mode != "auto" && mode != "authority" && mode != "provider" && mode != "client") {
        std::cout << "invalid mode; using auto\n";
        mode = "auto";
      }
      std::string bundleDir = trim(readLine("Bundle directory", ".easy-node-logs/incident_snapshot"));
      std::string composeProject = trim(readLine("Compose project name", "deploy"));
      bool includeDockerLogs = parseYesNo(readLine("Include docker log tails? (Y/n)", "y"), true);
      std::string dockerLogLines = trim(readLine("Docker log tail lines", "200"));
      std::string timeoutSec = trim(readLine("HTTP timeout sec", "8"));
      bool overrideEndpoints = parseYesNo(readLine("Override endpoint URLs manually? (y/N)", "n"), false);

      std::string directoryURL;
      std::string issuerURL;
      std::string entryURL;
      std::string exitURL;
      if (overrideEndpoints) {
        directoryURL = normalizeEndpointURL(readLine("Directory URL (optional)", ""), 8081);
        issuerURL = normalizeEndpointURL(readLine("Issuer URL (optional)", ""), 8082);
        entryURL = normalizeEndpointURL(readLine("Entry URL (optional)", ""), 8083);
        exitURL = normalizeEndpointURL(readLine("Exit URL (optional)", ""), 8084);
      }

      std::ostringstream cmd;
      cmd << shellEscape(script) << " incident-snapshot"
          << " --mode " << shellEscape(mode)
          << " --compose-project " << shellEscape(composeProject)
          << " --include-docker-logs " << (includeDockerLogs ? "1" : "0")
          << " --docker-log-lines " << shellEscape(dockerLogLines)
          << " --timeout-sec " << shellEscape(timeoutSec);
      if (!bundleDir.empty()) {
        cmd << " --bundle-dir " << shellEscape(bundleDir);
      }
      if (!directoryURL.empty()) {
        cmd << " --directory-url " << shellEscape(directoryURL);
      }
      if (!issuerURL.empty()) {
        cmd << " --issuer-url " << shellEscape(issuerURL);
      }
      if (!entryURL.empty()) {
        cmd << " --entry-url " << shellEscape(entryURL);
      }
      if (!exitURL.empty()) {
        cmd << " --exit-url " << shellEscape(exitURL);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "41") {
      std::string bundleDir = trim(readLine("Bundle directory override (optional)", ""));
      std::string runReportJsonDefault = bundleDir.empty() ? "" : (bundleDir + "/prod_bundle_run_report.json");
      if (runReportJsonDefault.empty()) {
        runReportJsonDefault = ".easy-node-logs/prod_gate_bundle/prod_bundle_run_report.json";
      }
      std::string runReportJson = trim(readLine("Run report JSON path (recommended)", runReportJsonDefault));
      std::string gateSummaryJson = trim(readLine("Gate summary JSON path (optional)", ""));
      std::string wgValidateSummaryJson = trim(readLine("WG validate summary JSON path (optional)", ""));
      std::string wgSoakSummaryJson = trim(readLine("WG soak summary JSON path (optional)", ""));
      bool requireFullSequence = parseYesNo(readLine("Require full gate sequence status=ok? (Y/n)", "y"), true);
      bool requireWGValidate = parseYesNo(readLine("Require WG validate status=ok? (Y/n)", "y"), true);
      bool requireWGSoak = parseYesNo(readLine("Require WG soak status=ok? (Y/n)", "y"), true);
      std::string maxWGSoakFailedRounds = trim(readLine("Max WG soak failed rounds", "0"));
      bool requireRunReportStages = parseYesNo(readLine("Require run-report stages (preflight + bundle + integrity + signoff) to be ok? (y/N)", "n"), false);
      bool failOnNoGo = parseYesNo(readLine("Return non-zero when decision is NO-GO? (y/N)", "n"), false);
      bool showJson = parseYesNo(readLine("Show summary JSON payloads? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-gate-slo-summary"
          << " --require-full-sequence " << (requireFullSequence ? "1" : "0")
          << " --require-wg-validate-ok " << (requireWGValidate ? "1" : "0")
          << " --require-wg-soak-ok " << (requireWGSoak ? "1" : "0")
          << " --require-wg-validate-udp-source 1"
          << " --require-wg-validate-strict-distinct 1"
          << " --require-wg-soak-diversity-pass 1"
          << " --min-wg-soak-selection-lines 8"
          << " --min-wg-soak-entry-operators 2"
          << " --min-wg-soak-exit-operators 2"
          << " --min-wg-soak-cross-operator-pairs 1"
          << " --max-wg-soak-failed-rounds " << shellEscape(maxWGSoakFailedRounds)
          << " --require-preflight-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-bundle-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-integrity-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-signoff-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireRunReportStages ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireRunReportStages ? "1" : "0")
          << " --fail-on-no-go " << (failOnNoGo ? "1" : "0")
          << " --show-json " << (showJson ? "1" : "0");
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson);
      }
      if (!bundleDir.empty()) {
        cmd << " --bundle-dir " << shellEscape(bundleDir);
      }
      if (!gateSummaryJson.empty()) {
        cmd << " --gate-summary-json " << shellEscape(gateSummaryJson);
      }
      if (!wgValidateSummaryJson.empty()) {
        cmd << " --wg-validate-summary-json " << shellEscape(wgValidateSummaryJson);
      }
      if (!wgSoakSummaryJson.empty()) {
        cmd << " --wg-soak-summary-json " << shellEscape(wgSoakSummaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "42") {
      std::string reportsDir = trim(readLine("Reports directory (scan for prod_bundle_run_report.json)", ".easy-node-logs"));
      std::string maxReports = trim(readLine("Max reports to evaluate", "25"));
      std::string sinceHours = trim(readLine("Include only reports from last N hours (0=all)", "0"));
      bool requireFullSequence = parseYesNo(readLine("Require full gate sequence status=ok? (Y/n)", "y"), true);
      bool requireWGValidate = parseYesNo(readLine("Require WG validate status=ok? (Y/n)", "y"), true);
      bool requireWGSoak = parseYesNo(readLine("Require WG soak status=ok? (Y/n)", "y"), true);
      std::string maxWGSoakFailedRounds = trim(readLine("Max WG soak failed rounds", "0"));
      bool requireRunReportStages = parseYesNo(readLine("Require run-report stages (preflight + bundle + integrity + signoff) to be ok? (y/N)", "n"), false);
      bool failOnAnyNoGo = parseYesNo(readLine("Fail if any run is NO-GO? (y/N)", "n"), false);
      std::string minGoRatePct = trim(readLine("Minimum GO rate percent (0-100)", "0"));
      bool showDetails = parseYesNo(readLine("Show per-run details? (Y/n)", "y"), true);
      std::string showTopReasons = trim(readLine("Show top no-go reasons (count)", "5"));
      std::string summaryJson = trim(readLine("Summary JSON output path (optional)", ""));
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON payload to console? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-gate-slo-trend"
          << " --max-reports " << shellEscape(maxReports)
          << " --since-hours " << shellEscape(sinceHours)
          << " --require-full-sequence " << (requireFullSequence ? "1" : "0")
          << " --require-wg-validate-ok " << (requireWGValidate ? "1" : "0")
          << " --require-wg-soak-ok " << (requireWGSoak ? "1" : "0")
          << " --require-wg-validate-udp-source 1"
          << " --require-wg-validate-strict-distinct 1"
          << " --require-wg-soak-diversity-pass 1"
          << " --min-wg-soak-selection-lines 8"
          << " --min-wg-soak-entry-operators 2"
          << " --min-wg-soak-exit-operators 2"
          << " --min-wg-soak-cross-operator-pairs 1"
          << " --max-wg-soak-failed-rounds " << shellEscape(maxWGSoakFailedRounds)
          << " --require-preflight-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-bundle-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-integrity-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-signoff-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireRunReportStages ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireRunReportStages ? "1" : "0")
          << " --fail-on-any-no-go " << (failOnAnyNoGo ? "1" : "0")
          << " --min-go-rate-pct " << shellEscape(minGoRatePct)
          << " --show-details " << (showDetails ? "1" : "0")
          << " --show-top-reasons " << shellEscape(showTopReasons)
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "43") {
      bool useTrendSummary = parseYesNo(readLine("Use existing trend summary JSON file? (y/N)", "n"), false);
      std::string trendSummaryJson;
      std::string reportsDir;
      std::string maxReports = "25";
      std::string sinceHours = "24";
      if (useTrendSummary) {
        trendSummaryJson = trim(readLine("Trend summary JSON path", ".easy-node-logs/prod_slo_trend_24h.json"));
      } else {
        reportsDir = trim(readLine("Reports directory (scan for prod_bundle_run_report.json)", ".easy-node-logs"));
        maxReports = trim(readLine("Max reports to evaluate", "25"));
        sinceHours = trim(readLine("Include only reports from last N hours (0=all)", "24"));
      }

      std::string warnGoRatePct = trim(readLine("WARN when GO rate below percent", "98"));
      std::string criticalGoRatePct = trim(readLine("CRITICAL when GO rate below percent", "90"));
      std::string warnNoGoCount = trim(readLine("WARN when NO-GO count >=", "1"));
      std::string criticalNoGoCount = trim(readLine("CRITICAL when NO-GO count >=", "2"));
      std::string warnEvalErrors = trim(readLine("WARN when evaluation errors >=", "1"));
      std::string criticalEvalErrors = trim(readLine("CRITICAL when evaluation errors >=", "2"));
      bool failOnWarn = parseYesNo(readLine("Return non-zero on WARN? (y/N)", "n"), false);
      bool failOnCritical = parseYesNo(readLine("Return non-zero on CRITICAL? (y/N)", "n"), false);
      std::string showTopReasons = trim(readLine("Top no-go reasons to include", "5"));
      std::string summaryJson = trim(readLine("Alert summary JSON output path (optional)", ""));
      bool printSummaryJson = parseYesNo(readLine("Print alert summary JSON payload to console? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-gate-slo-alert"
          << " --require-wg-validate-udp-source 1"
          << " --require-wg-validate-strict-distinct 1"
          << " --require-wg-soak-diversity-pass 1"
          << " --min-wg-soak-selection-lines 8"
          << " --min-wg-soak-entry-operators 2"
          << " --min-wg-soak-exit-operators 2"
          << " --min-wg-soak-cross-operator-pairs 1"
          << " --warn-go-rate-pct " << shellEscape(warnGoRatePct)
          << " --critical-go-rate-pct " << shellEscape(criticalGoRatePct)
          << " --warn-no-go-count " << shellEscape(warnNoGoCount)
          << " --critical-no-go-count " << shellEscape(criticalNoGoCount)
          << " --warn-eval-errors " << shellEscape(warnEvalErrors)
          << " --critical-eval-errors " << shellEscape(criticalEvalErrors)
          << " --fail-on-warn " << (failOnWarn ? "1" : "0")
          << " --fail-on-critical " << (failOnCritical ? "1" : "0")
          << " --show-top-reasons " << shellEscape(showTopReasons)
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");

      if (useTrendSummary) {
        if (!trendSummaryJson.empty()) {
          cmd << " --trend-summary-json " << shellEscape(trendSummaryJson);
        }
      } else {
        if (!reportsDir.empty()) {
          cmd << " --reports-dir " << shellEscape(reportsDir);
        }
        cmd << " --max-reports " << shellEscape(maxReports)
            << " --since-hours " << shellEscape(sinceHours);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "44") {
      std::string reportsDir = trim(readLine("Reports directory (scan for prod_bundle_run_report.json)", ".easy-node-logs"));
      std::string maxReports = trim(readLine("Max reports to evaluate", "25"));
      std::string sinceHours = trim(readLine("Include only reports from last N hours (0=all)", "24"));
      bool requireFullSequence = parseYesNo(readLine("Require full gate sequence status=ok? (Y/n)", "y"), true);
      bool requireWGValidate = parseYesNo(readLine("Require WG validate status=ok? (Y/n)", "y"), true);
      bool requireWGSoak = parseYesNo(readLine("Require WG soak status=ok? (Y/n)", "y"), true);
      std::string maxWGSoakFailedRounds = trim(readLine("Max WG soak failed rounds", "0"));
      bool requireRunReportStages = parseYesNo(readLine("Require run-report stages (preflight + bundle + integrity + signoff) to be ok? (y/N)", "n"), false);
      bool failOnAnyNoGo = parseYesNo(readLine("Fail if any run is NO-GO? (y/N)", "n"), false);
      std::string minGoRatePct = trim(readLine("Minimum GO rate percent (0-100)", "95"));
      std::string showTopReasons = trim(readLine("Top no-go reasons to include", "5"));

      std::string warnGoRatePct = trim(readLine("WARN when GO rate below percent", "98"));
      std::string criticalGoRatePct = trim(readLine("CRITICAL when GO rate below percent", "90"));
      std::string warnNoGoCount = trim(readLine("WARN when NO-GO count >=", "1"));
      std::string criticalNoGoCount = trim(readLine("CRITICAL when NO-GO count >=", "2"));
      std::string warnEvalErrors = trim(readLine("WARN when evaluation errors >=", "1"));
      std::string criticalEvalErrors = trim(readLine("CRITICAL when evaluation errors >=", "2"));
      bool failOnWarn = parseYesNo(readLine("Return non-zero on WARN? (y/N)", "n"), false);
      bool failOnCritical = parseYesNo(readLine("Return non-zero on CRITICAL? (y/N)", "n"), false);

      std::string trendSummaryJson = trim(readLine("Trend summary JSON output path (optional)", ".easy-node-logs/prod_slo_trend_24h.json"));
      std::string alertSummaryJson = trim(readLine("Alert summary JSON output path (optional)", ".easy-node-logs/prod_slo_alert_24h.json"));
      std::string dashboardMd = trim(readLine("Dashboard markdown output path (optional)", ".easy-node-logs/prod_slo_dashboard_24h.md"));
      bool printDashboard = parseYesNo(readLine("Print dashboard markdown after generation? (Y/n)", "y"), true);
      bool printSummaryJson = parseYesNo(readLine("Print trend/alert JSON payloads to console? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-gate-slo-dashboard"
          << " --max-reports " << shellEscape(maxReports)
          << " --since-hours " << shellEscape(sinceHours)
          << " --require-full-sequence " << (requireFullSequence ? "1" : "0")
          << " --require-wg-validate-ok " << (requireWGValidate ? "1" : "0")
          << " --require-wg-soak-ok " << (requireWGSoak ? "1" : "0")
          << " --require-wg-validate-udp-source 1"
          << " --require-wg-validate-strict-distinct 1"
          << " --require-wg-soak-diversity-pass 1"
          << " --min-wg-soak-selection-lines 8"
          << " --min-wg-soak-entry-operators 2"
          << " --min-wg-soak-exit-operators 2"
          << " --min-wg-soak-cross-operator-pairs 1"
          << " --max-wg-soak-failed-rounds " << shellEscape(maxWGSoakFailedRounds)
          << " --require-preflight-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-bundle-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-integrity-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-signoff-ok " << (requireRunReportStages ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireRunReportStages ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireRunReportStages ? "1" : "0")
          << " --fail-on-any-no-go " << (failOnAnyNoGo ? "1" : "0")
          << " --min-go-rate-pct " << shellEscape(minGoRatePct)
          << " --show-top-reasons " << shellEscape(showTopReasons)
          << " --warn-go-rate-pct " << shellEscape(warnGoRatePct)
          << " --critical-go-rate-pct " << shellEscape(criticalGoRatePct)
          << " --warn-no-go-count " << shellEscape(warnNoGoCount)
          << " --critical-no-go-count " << shellEscape(criticalNoGoCount)
          << " --warn-eval-errors " << shellEscape(warnEvalErrors)
          << " --critical-eval-errors " << shellEscape(criticalEvalErrors)
          << " --fail-on-warn " << (failOnWarn ? "1" : "0")
          << " --fail-on-critical " << (failOnCritical ? "1" : "0")
          << " --print-dashboard " << (printDashboard ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!trendSummaryJson.empty()) {
        cmd << " --trend-summary-json " << shellEscape(trendSummaryJson);
      }
      if (!alertSummaryJson.empty()) {
        cmd << " --alert-summary-json " << shellEscape(alertSummaryJson);
      }
      if (!dashboardMd.empty()) {
        cmd << " --dashboard-md " << shellEscape(dashboardMd);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "45") {
      std::string mode = trim(readLine("Mode (auto/authority/provider)", "auto"));
      if (mode != "auto" && mode != "authority" && mode != "provider") {
        std::cout << "invalid mode; using auto\n";
        mode = "auto";
      }
      std::string backupDir = trim(readLine("Backup directory", ".easy-node-logs/prod_key_rotation_manual"));
      std::string summaryJson = trim(readLine("Summary JSON path (optional)", ""));
      bool preflightCheck = parseYesNo(readLine("Run prod preflight before/after rotation? (Y/n)", "y"), true);
      bool preflightLive = parseYesNo(readLine("Use live endpoint checks in preflight? (y/N)", "n"), false);
      std::string preflightTimeout = trim(readLine("Preflight timeout sec", "12"));
      bool rotateServerSecrets = parseYesNo(readLine("Rotate local server secrets? (Y/n)", "y"), true);
      bool rotateAdminSigning = parseYesNo(readLine("Rotate admin signing key (authority mode)? (Y/n)", "y"), true);
      std::string keyHistory = trim(readLine("Admin signing key history", "3"));
      bool restart = parseYesNo(readLine("Restart services after secret rotation? (Y/n)", "y"), true);
      bool restartIssuer = parseYesNo(readLine("Restart issuer after signing-key rotation? (Y/n)", "y"), true);
      bool rollbackOnFail = parseYesNo(readLine("Auto-rollback on failure? (Y/n)", "y"), true);
      bool restartAfterRollback = parseYesNo(readLine("Restart services after rollback? (Y/n)", "y"), true);
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON payload? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-key-rotation-runbook"
          << " --mode " << shellEscape(mode)
          << " --preflight-check " << (preflightCheck ? "1" : "0")
          << " --preflight-live " << (preflightLive ? "1" : "0")
          << " --preflight-timeout-sec " << shellEscape(preflightTimeout)
          << " --rotate-server-secrets " << (rotateServerSecrets ? "1" : "0")
          << " --rotate-admin-signing " << (rotateAdminSigning ? "1" : "0")
          << " --key-history " << shellEscape(keyHistory)
          << " --restart " << (restart ? "1" : "0")
          << " --restart-issuer " << (restartIssuer ? "1" : "0")
          << " --rollback-on-fail " << (rollbackOnFail ? "1" : "0")
          << " --restart-after-rollback " << (restartAfterRollback ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!backupDir.empty()) {
        cmd << " --backup-dir " << shellEscape(backupDir);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "46") {
      std::string mode = trim(readLine("Mode (auto/authority/provider)", "auto"));
      if (mode != "auto" && mode != "authority" && mode != "provider") {
        std::cout << "invalid mode; using auto\n";
        mode = "auto";
      }
      std::string backupDir = trim(readLine("Backup directory", ".easy-node-logs/prod_upgrade_manual"));
      std::string summaryJson = trim(readLine("Summary JSON path (optional)", ""));
      bool preflightCheck = parseYesNo(readLine("Run prod preflight before/after upgrade? (Y/n)", "y"), true);
      bool preflightLive = parseYesNo(readLine("Use live endpoint checks in preflight? (y/N)", "n"), false);
      std::string preflightTimeout = trim(readLine("Preflight timeout sec", "12"));
      bool composePull = parseYesNo(readLine("Run docker compose pull? (Y/n)", "y"), true);
      bool composeBuild = parseYesNo(readLine("Run docker compose build? (y/N)", "n"), false);
      bool restart = parseYesNo(readLine("Restart compose services after upgrade steps? (Y/n)", "y"), true);
      bool rollbackOnFail = parseYesNo(readLine("Auto-rollback on failure? (Y/n)", "y"), true);
      bool restartAfterRollback = parseYesNo(readLine("Restart services after rollback? (Y/n)", "y"), true);
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON payload? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-upgrade-runbook"
          << " --mode " << shellEscape(mode)
          << " --preflight-check " << (preflightCheck ? "1" : "0")
          << " --preflight-live " << (preflightLive ? "1" : "0")
          << " --preflight-timeout-sec " << shellEscape(preflightTimeout)
          << " --compose-pull " << (composePull ? "1" : "0")
          << " --compose-build " << (composeBuild ? "1" : "0")
          << " --restart " << (restart ? "1" : "0")
          << " --rollback-on-fail " << (rollbackOnFail ? "1" : "0")
          << " --restart-after-rollback " << (restartAfterRollback ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!backupDir.empty()) {
        cmd << " --backup-dir " << shellEscape(backupDir);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "47") {
      std::string action = trim(readLine("Action (onboard/offboard)", "onboard"));
      if (action != "onboard" && action != "offboard") {
        std::cout << "invalid action; using onboard\n";
        action = "onboard";
      }

      std::string mode = trim(readLine("Mode (auto/authority/provider)", "auto"));
      if (mode != "auto" && mode != "authority" && mode != "provider") {
        std::cout << "invalid mode; using auto\n";
        mode = "auto";
      }

      std::string publicHost = trim(readLine("Public host/IP (optional, used for onboard checks)", ""));
      std::string operatorId = trim(readLine("Operator ID (optional; default from env/mode)", ""));
      std::string authorityDir = trim(readLine("Authority directory URL (provider onboard)", ""));
      std::string authorityIssuer = trim(readLine("Authority issuer URL (provider onboard)", ""));
      std::string peerDirs = trim(readLine("Peer directories CSV (optional)", ""));
      bool preflightCheck = parseYesNo(readLine("Run preflight in onboard action? (Y/n)", "y"), true);
      std::string preflightTimeout = trim(readLine("Preflight timeout sec", "30"));
      bool healthCheck = parseYesNo(readLine("Run health checks in onboard action? (Y/n)", "y"), true);
      std::string healthTimeout = trim(readLine("Health timeout sec", "60"));
      std::string directoryUrl = trim(readLine("Directory URL for relay verification", ""));
      bool verifyRelays = parseYesNo(readLine("Verify relay publication on onboard? (Y/n)", "y"), true);
      bool verifyAbsent = parseYesNo(readLine("Verify relay absence on offboard? (Y/n)", "y"), true);
      std::string verifyRelayTimeout = trim(readLine("Relay verify timeout sec", "90"));
      std::string verifyRelayMinCount = trim(readLine("Relay verify min count (onboard)", "2"));
      std::string summaryJson = trim(readLine("Summary JSON path (optional)", ""));
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON payload? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-operator-lifecycle-runbook"
          << " --action " << shellEscape(action)
          << " --mode " << shellEscape(mode)
          << " --preflight-check " << (preflightCheck ? "1" : "0")
          << " --preflight-timeout-sec " << shellEscape(preflightTimeout)
          << " --health-check " << (healthCheck ? "1" : "0")
          << " --health-timeout-sec " << shellEscape(healthTimeout)
          << " --verify-relays " << (verifyRelays ? "1" : "0")
          << " --verify-absent " << (verifyAbsent ? "1" : "0")
          << " --verify-relay-timeout-sec " << shellEscape(verifyRelayTimeout)
          << " --verify-relay-min-count " << shellEscape(verifyRelayMinCount)
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!publicHost.empty()) {
        cmd << " --public-host " << shellEscape(publicHost);
      }
      if (!operatorId.empty()) {
        cmd << " --operator-id " << shellEscape(operatorId);
      }
      if (!authorityDir.empty()) {
        cmd << " --authority-directory " << shellEscape(authorityDir);
      }
      if (!authorityIssuer.empty()) {
        cmd << " --authority-issuer " << shellEscape(authorityIssuer);
      }
      if (!peerDirs.empty()) {
        cmd << " --peer-directories " << shellEscape(peerDirs);
      }
      if (!directoryUrl.empty()) {
        cmd << " --directory-url " << shellEscape(directoryUrl);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "48") {
      std::string rounds = trim(readLine("Cohort rounds", "5"));
      std::string pauseSec = trim(readLine("Pause between rounds (sec)", "60"));
      bool continueOnFail = parseYesNo(readLine("Continue running after a failed round? (y/N)", "n"), false);
      bool requireAllRoundsOk = parseYesNo(readLine("Require all rounds to pass for cohort success? (Y/n)", "y"), true);
      std::string trendMinGoRate = trim(readLine("Minimum GO rate percent", "95"));
      std::string maxRoundFailures = trim(readLine("Max failed rounds allowed for signoff", "0"));
      std::string maxAlertSeverity = trim(readLine("Max alert severity allowed (OK/WARN/CRITICAL)", "WARN"));
      std::string maxAlertSeverityUpper = upperCopy(maxAlertSeverity);
      if (maxAlertSeverityUpper != "OK" && maxAlertSeverityUpper != "WARN" && maxAlertSeverityUpper != "CRITICAL") {
        std::cout << "invalid max alert severity; using WARN\n";
        maxAlertSeverityUpper = "WARN";
      }
      bool bundleOutputs = parseYesNo(readLine("Generate cohort bundle artifacts (tar + sha256 + manifest)? (Y/n)", "y"), true);
      bool bundleFailClose = parseYesNo(readLine("Fail cohort if bundle generation fails? (Y/n)", "y"), true);
      std::string reportsDir = trim(readLine("Reports directory (optional)", ""));
      std::string summaryJson = trim(readLine("Cohort summary JSON path (optional)", ""));
      bool printSummaryJson = parseYesNo(readLine("Print cohort summary JSON payload? (y/N)", "n"), false);
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness once before the cohort? (Y/n)", "y"), true);
      std::string extraArgs = trim(readLine("Extra prod-pilot-runbook args after '--' (optional)", ""));

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-runbook"
          << " --rounds " << shellEscape(rounds)
          << " --pause-sec " << shellEscape(pauseSec)
          << " --continue-on-fail " << (continueOnFail ? "1" : "0")
          << " --require-all-rounds-ok " << (requireAllRoundsOk ? "1" : "0")
          << " --trend-min-go-rate-pct " << shellEscape(trendMinGoRate)
          << " --trend-require-wg-validate-udp-source 1"
          << " --trend-require-wg-validate-strict-distinct 1"
          << " --trend-require-wg-soak-diversity-pass 1"
          << " --trend-min-wg-soak-selection-lines 12"
          << " --trend-min-wg-soak-entry-operators 2"
          << " --trend-min-wg-soak-exit-operators 2"
          << " --trend-min-wg-soak-cross-operator-pairs 2"
          << " --max-alert-severity " << shellEscape(maxAlertSeverityUpper)
          << " --bundle-outputs " << (bundleOutputs ? "1" : "0")
          << " --bundle-fail-close " << (bundleFailClose ? "1" : "0")
          << " --pre-real-host-readiness " << (runPreRealHostReadiness ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      if (!extraArgs.empty()) {
        cmd << " -- " << extraArgs;
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "49") {
      std::string summaryJson = trim(readLine("Cohort summary JSON path (recommended)", ".easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json"));
      std::string reportsDir = trim(readLine("Cohort reports dir (optional)", ""));
      std::string bundleTar = trim(readLine("Cohort bundle tar path (optional)", ""));
      std::string bundleSha = trim(readLine("Cohort bundle sha256 sidecar path (optional)", ""));
      std::string bundleManifest = trim(readLine("Cohort bundle manifest path (optional)", ""));
      bool checkTar = parseYesNo(readLine("Check tar checksum sidecar? (Y/n)", "y"), true);
      bool checkManifest = parseYesNo(readLine("Check manifest + round structure? (Y/n)", "y"), true);
      bool showDetails = parseYesNo(readLine("Show detailed verification output? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-bundle-verify"
          << " --check-tar-sha256 " << (checkTar ? "1" : "0")
          << " --check-manifest " << (checkManifest ? "1" : "0")
          << " --show-details " << (showDetails ? "1" : "0");
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!bundleTar.empty()) {
        cmd << " --bundle-tar " << shellEscape(bundleTar);
      }
      if (!bundleSha.empty()) {
        cmd << " --bundle-sha256-file " << shellEscape(bundleSha);
      }
      if (!bundleManifest.empty()) {
        cmd << " --bundle-manifest-json " << shellEscape(bundleManifest);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "50") {
      std::string summaryJson = trim(readLine("Cohort summary JSON path (recommended)", ".easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json"));
      std::string reportsDir = trim(readLine("Cohort reports dir (optional)", ""));
      std::string bundleTar = trim(readLine("Cohort bundle tar path (optional)", ""));
      std::string bundleSha = trim(readLine("Cohort bundle sha256 sidecar path (optional)", ""));
      std::string bundleManifest = trim(readLine("Cohort bundle manifest path (optional)", ""));
      bool checkTar = parseYesNo(readLine("Check tar checksum sidecar? (Y/n)", "y"), true);
      bool checkManifest = parseYesNo(readLine("Check manifest + round structure? (Y/n)", "y"), true);
      bool showIntegrityDetails = parseYesNo(readLine("Show integrity verification details? (y/N)", "n"), false);
      bool requireStatusOk = parseYesNo(readLine("Require cohort status=ok? (Y/n)", "y"), true);
      bool requireAllRoundsOk = parseYesNo(readLine("Require all rounds to pass? (Y/n)", "y"), true);
      std::string maxRoundFailures = trim(readLine("Max round failures allowed", "0"));
      bool requireTrendGo = parseYesNo(readLine("Require trend decision GO? (Y/n)", "y"), true);
      std::string minGoRate = trim(readLine("Minimum GO rate percent", "95"));
      std::string maxAlertSeverity = trim(readLine("Max alert severity allowed (OK/WARN/CRITICAL)", "WARN"));
      std::string maxAlertSeverityUpper = upperCopy(maxAlertSeverity);
      if (maxAlertSeverityUpper != "OK" && maxAlertSeverityUpper != "WARN" && maxAlertSeverityUpper != "CRITICAL") {
        std::cout << "invalid max alert severity; using WARN\n";
        maxAlertSeverityUpper = "WARN";
      }
      bool requireBundleCreated = parseYesNo(readLine("Require bundle.created=true? (Y/n)", "y"), true);
      bool requireBundleManifest = parseYesNo(readLine("Require bundle manifest artifact present? (Y/n)", "y"), true);
      bool showJson = parseYesNo(readLine("Show policy summary JSON output? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-signoff"
          << " --check-tar-sha256 " << (checkTar ? "1" : "0")
          << " --check-manifest " << (checkManifest ? "1" : "0")
          << " --show-integrity-details " << (showIntegrityDetails ? "1" : "0")
          << " --require-status-ok " << (requireStatusOk ? "1" : "0")
          << " --require-all-rounds-ok " << (requireAllRoundsOk ? "1" : "0")
          << " --max-round-failures " << shellEscape(maxRoundFailures)
          << " --require-trend-go " << (requireTrendGo ? "1" : "0")
          << " --require-trend-artifact-policy-match 1"
          << " --require-trend-wg-validate-udp-source 1"
          << " --require-trend-wg-validate-strict-distinct 1"
          << " --require-trend-wg-soak-diversity-pass 1"
          << " --min-trend-wg-soak-selection-lines 12"
          << " --min-trend-wg-soak-entry-operators 2"
          << " --min-trend-wg-soak-exit-operators 2"
          << " --min-trend-wg-soak-cross-operator-pairs 2"
          << " --min-go-rate-pct " << shellEscape(minGoRate)
          << " --max-alert-severity " << shellEscape(maxAlertSeverityUpper)
          << " --require-bundle-created " << (requireBundleCreated ? "1" : "0")
          << " --require-bundle-manifest " << (requireBundleManifest ? "1" : "0")
          << " --show-json " << (showJson ? "1" : "0");
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!bundleTar.empty()) {
        cmd << " --bundle-tar " << shellEscape(bundleTar);
      }
      if (!bundleSha.empty()) {
        cmd << " --bundle-sha256-file " << shellEscape(bundleSha);
      }
      if (!bundleManifest.empty()) {
        cmd << " --bundle-manifest-json " << shellEscape(bundleManifest);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "51") {
      std::string rounds = trim(readLine("Cohort rounds", "5"));
      std::string pauseSec = trim(readLine("Pause between rounds (sec)", "60"));
      bool continueOnFail = parseYesNo(readLine("Continue running after a failed round? (y/N)", "n"), false);
      bool requireAllRoundsOk = parseYesNo(readLine("Require all rounds to pass for cohort success? (Y/n)", "y"), true);
      std::string trendMinGoRate = trim(readLine("Minimum GO rate percent", "95"));
      std::string maxAlertSeverity = trim(readLine("Max alert severity allowed (OK/WARN/CRITICAL)", "WARN"));
      std::string maxAlertSeverityUpper = upperCopy(maxAlertSeverity);
      if (maxAlertSeverityUpper != "OK" && maxAlertSeverityUpper != "WARN" && maxAlertSeverityUpper != "CRITICAL") {
        std::cout << "invalid max alert severity; using WARN\n";
        maxAlertSeverityUpper = "WARN";
      }
      bool bundleOutputs = parseYesNo(readLine("Generate cohort bundle artifacts (tar + sha256 + manifest)? (Y/n)", "y"), true);
      bool bundleFailClose = parseYesNo(readLine("Fail cohort if bundle generation fails? (Y/n)", "y"), true);
      std::string reportsDir = trim(readLine("Reports directory", ".easy-node-logs/prod_pilot_cohort"));
      std::string summaryJson = trim(readLine("Cohort summary JSON path", ".easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json"));
      bool printRunbookSummary = parseYesNo(readLine("Print runbook summary JSON payload? (y/N)", "n"), false);
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness once before the cohort? (Y/n)", "y"), true);
      bool signoffCheckTar = parseYesNo(readLine("Signoff: check tar checksum sidecar? (Y/n)", "y"), true);
      bool signoffCheckManifest = parseYesNo(readLine("Signoff: check manifest + round structure? (Y/n)", "y"), true);
      bool signoffShowIntegrity = parseYesNo(readLine("Signoff: show integrity details? (y/N)", "n"), false);
      bool signoffShowJson = parseYesNo(readLine("Signoff: show policy summary JSON output? (y/N)", "n"), false);
      std::string extraArgs = trim(readLine("Extra prod-pilot-runbook args after '--' (optional)", ""));

      std::ostringstream runbookCmd;
      runbookCmd << shellEscape(script) << " prod-pilot-cohort-runbook"
                 << " --rounds " << shellEscape(rounds)
                 << " --pause-sec " << shellEscape(pauseSec)
                 << " --continue-on-fail " << (continueOnFail ? "1" : "0")
                 << " --require-all-rounds-ok " << (requireAllRoundsOk ? "1" : "0")
                 << " --trend-min-go-rate-pct " << shellEscape(trendMinGoRate)
                 << " --trend-require-wg-validate-udp-source 1"
                 << " --trend-require-wg-validate-strict-distinct 1"
                 << " --trend-require-wg-soak-diversity-pass 1"
                 << " --trend-min-wg-soak-selection-lines 12"
                 << " --trend-min-wg-soak-entry-operators 2"
                 << " --trend-min-wg-soak-exit-operators 2"
                 << " --trend-min-wg-soak-cross-operator-pairs 2"
                 << " --max-alert-severity " << shellEscape(maxAlertSeverityUpper)
                 << " --bundle-outputs " << (bundleOutputs ? "1" : "0")
                 << " --bundle-fail-close " << (bundleFailClose ? "1" : "0")
                 << " --pre-real-host-readiness " << (runPreRealHostReadiness ? "1" : "0")
                 << " --reports-dir " << shellEscape(reportsDir)
                 << " --summary-json " << shellEscape(summaryJson)
                 << " --print-summary-json " << (printRunbookSummary ? "1" : "0");
      if (!extraArgs.empty()) {
        runbookCmd << " -- " << extraArgs;
      }

      int runbookRc = runCommand(runbookCmd.str());
      std::filesystem::path summaryPath(summaryJson);
      if (summaryPath.is_relative()) {
        summaryPath = std::filesystem::path(root) / summaryPath;
      }
      bool summaryExists = std::filesystem::exists(summaryPath);
      if (runbookRc != 0 && !summaryExists) {
        std::cout << "runbook failed and summary JSON not found; skipping signoff\n";
        continue;
      }
      if (runbookRc != 0) {
        std::cout << "runbook failed but summary JSON exists; running signoff for explicit fail-close result\n";
      }

      std::ostringstream signoffCmd;
      signoffCmd << shellEscape(script) << " prod-pilot-cohort-signoff"
                 << " --summary-json " << shellEscape(summaryJson)
                 << " --reports-dir " << shellEscape(reportsDir)
                 << " --check-tar-sha256 " << (signoffCheckTar ? "1" : "0")
                 << " --check-manifest " << (signoffCheckManifest ? "1" : "0")
                 << " --show-integrity-details " << (signoffShowIntegrity ? "1" : "0")
                 << " --require-status-ok 1"
                 << " --require-all-rounds-ok " << (requireAllRoundsOk ? "1" : "0")
                 << " --max-round-failures 0"
                 << " --require-trend-go 1"
                 << " --require-trend-artifact-policy-match 1"
                 << " --require-trend-wg-validate-udp-source 1"
                 << " --require-trend-wg-validate-strict-distinct 1"
                 << " --require-trend-wg-soak-diversity-pass 1"
                 << " --min-trend-wg-soak-selection-lines 12"
                 << " --min-trend-wg-soak-entry-operators 2"
                 << " --min-trend-wg-soak-exit-operators 2"
                 << " --min-trend-wg-soak-cross-operator-pairs 2"
                 << " --min-go-rate-pct " << shellEscape(trendMinGoRate)
                 << " --max-alert-severity " << shellEscape(maxAlertSeverityUpper)
                 << " --require-bundle-created " << (bundleOutputs ? "1" : "0")
                 << " --require-bundle-manifest " << (bundleOutputs ? "1" : "0")
                 << " --show-json " << (signoffShowJson ? "1" : "0");
      runCommand(signoffCmd.str());
      continue;
    }
    if (choice == "52") {
      std::string bootstrapDefault = endpointFromHost(hosts.aHost, 8081);
      std::string bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
      std::string subject = trim(readLine("Client subject/invite key", "pilot-client"));
      std::string rounds = trim(readLine("Cohort rounds", "5"));
      std::string pauseSec = trim(readLine("Pause between rounds (sec)", "60"));
      std::string trendMinGoRate = trim(readLine("Minimum GO rate percent", "95"));
      std::string maxRoundFailures = trim(readLine("Max failed rounds allowed for signoff", "0"));
      std::string maxAlertSeverity = trim(readLine("Max alert severity allowed (OK/WARN/CRITICAL)", "WARN"));
      std::string maxAlertSeverityUpper = upperCopy(maxAlertSeverity);
      if (maxAlertSeverityUpper != "OK" && maxAlertSeverityUpper != "WARN" && maxAlertSeverityUpper != "CRITICAL") {
        std::cout << "invalid max alert severity; using WARN\n";
        maxAlertSeverityUpper = "WARN";
      }
      bool continueOnFail = parseYesNo(readLine("Continue running after a failed round? (y/N)", "n"), false);
      bool requireAllRoundsOk = parseYesNo(readLine("Require all rounds to pass? (Y/n)", "y"), true);
      bool bundleOutputs = parseYesNo(readLine("Require bundle outputs in runbook/signoff? (Y/n)", "y"), true);
      bool bundleFailClose = parseYesNo(readLine("Fail if bundle generation stage fails? (Y/n)", "y"), true);
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness once before the cohort? (Y/n)", "y"), true);
      bool showJson = parseYesNo(readLine("Show runbook/signoff JSON payloads? (y/N)", "n"), false);
      std::string reportsDir = trim(readLine("Reports directory (optional)", ""));
      std::string summaryJson = trim(readLine("Summary JSON path (optional)", ""));
      std::string runReportJson = trim(readLine("Quick run report JSON path (optional)", ""));
      bool printRunReport = parseYesNo(readLine("Print quick run report JSON payload? (y/N)", "n"), false);
      std::string extraArgs = trim(readLine("Extra prod-pilot-runbook args after '--' (optional)", ""));

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-quick"
          << " --bootstrap-directory " << shellEscape(bootstrapDir)
          << " --subject " << shellEscape(subject)
          << " --rounds " << shellEscape(rounds)
          << " --pause-sec " << shellEscape(pauseSec)
          << " --continue-on-fail " << (continueOnFail ? "1" : "0")
          << " --require-all-rounds-ok " << (requireAllRoundsOk ? "1" : "0")
          << " --max-round-failures " << shellEscape(maxRoundFailures)
          << " --trend-min-go-rate-pct " << shellEscape(trendMinGoRate)
          << " --max-alert-severity " << shellEscape(maxAlertSeverityUpper)
          << " --bundle-outputs " << (bundleOutputs ? "1" : "0")
          << " --bundle-fail-close " << (bundleFailClose ? "1" : "0")
          << " --pre-real-host-readiness " << (runPreRealHostReadiness ? "1" : "0")
          << " --signoff-require-trend-artifact-policy-match 1"
          << " --signoff-require-trend-wg-validate-udp-source 1"
          << " --signoff-require-trend-wg-validate-strict-distinct 1"
          << " --signoff-require-trend-wg-soak-diversity-pass 1"
          << " --signoff-min-trend-wg-soak-selection-lines 12"
          << " --signoff-min-trend-wg-soak-entry-operators 2"
          << " --signoff-min-trend-wg-soak-exit-operators 2"
          << " --signoff-min-trend-wg-soak-cross-operator-pairs 2"
          << " --signoff-require-incident-snapshot-on-fail 1"
          << " --signoff-require-incident-snapshot-artifacts 1"
          << " --print-run-report " << (printRunReport ? "1" : "0")
          << " --show-json " << (showJson ? "1" : "0");
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson);
      }
      if (!extraArgs.empty()) {
        cmd << " -- " << extraArgs;
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "53") {
      std::string runReportJson = trim(readLine("Quick run report JSON path (recommended)", ".easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_quick_report.json"));
      std::string reportsDir = trim(readLine("Reports directory (optional)", ""));
      bool requireStatusOk = parseYesNo(readLine("Require quick status=ok? (Y/n)", "y"), true);
      bool requireRunbookOk = parseYesNo(readLine("Require runbook rc=0? (Y/n)", "y"), true);
      bool requireSignoffAttempted = parseYesNo(readLine("Require signoff attempted=true? (Y/n)", "y"), true);
      bool requireSignoffOk = parseYesNo(readLine("Require signoff rc=0? (Y/n)", "y"), true);
      bool requireCohortSignoffPolicy = parseYesNo(readLine("Re-validate strict cohort signoff policy? (Y/n)", "y"), true);
      bool requireSummaryJson = parseYesNo(readLine("Require summary JSON artifact exists? (Y/n)", "y"), true);
      bool requireSummaryStatusOk = parseYesNo(readLine("Require summary status=ok? (Y/n)", "y"), true);
      bool requireIncidentSnapshotOnFail = true;
      bool requireIncidentSnapshotArtifacts = true;
      std::string maxDurationSec = trim(readLine("Max duration sec (0=disabled)", "0"));
      bool showJson = parseYesNo(readLine("Show run report JSON payload? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-quick-check"
          << " --require-status-ok " << (requireStatusOk ? "1" : "0")
          << " --require-runbook-ok " << (requireRunbookOk ? "1" : "0")
          << " --require-signoff-attempted " << (requireSignoffAttempted ? "1" : "0")
          << " --require-signoff-ok " << (requireSignoffOk ? "1" : "0")
          << " --require-cohort-signoff-policy " << (requireCohortSignoffPolicy ? "1" : "0")
          << " --require-summary-json " << (requireSummaryJson ? "1" : "0")
          << " --require-summary-status-ok " << (requireSummaryStatusOk ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireIncidentSnapshotOnFail ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireIncidentSnapshotArtifacts ? "1" : "0")
          << " --max-duration-sec " << shellEscape(maxDurationSec)
          << " --show-json " << (showJson ? "1" : "0");
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson);
      }
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "54") {
      std::string reportsDir = trim(readLine("Reports directory (scan for quick run reports)", ".easy-node-logs"));
      std::string maxReports = trim(readLine("Max reports to evaluate", "25"));
      std::string sinceHours = trim(readLine("Include only reports from last N hours (0=all)", "24"));
      bool requireStatusOk = parseYesNo(readLine("Require quick status=ok? (Y/n)", "y"), true);
      bool requireRunbookOk = parseYesNo(readLine("Require runbook rc=0? (Y/n)", "y"), true);
      bool requireSignoffAttempted = parseYesNo(readLine("Require signoff attempted=true? (Y/n)", "y"), true);
      bool requireSignoffOk = parseYesNo(readLine("Require signoff rc=0? (Y/n)", "y"), true);
      bool requireCohortSignoffPolicy = parseYesNo(readLine("Re-validate strict cohort signoff policy? (Y/n)", "y"), true);
      bool requireSummaryJson = parseYesNo(readLine("Require summary JSON artifact exists? (Y/n)", "y"), true);
      bool requireSummaryStatusOk = parseYesNo(readLine("Require summary status=ok? (Y/n)", "y"), true);
      bool requireIncidentSnapshotOnFail = true;
      bool requireIncidentSnapshotArtifacts = true;
      std::string maxDurationSec = trim(readLine("Max duration sec (0=disabled)", "0"));
      bool failOnAnyNoGo = parseYesNo(readLine("Fail if any run is NO-GO? (y/N)", "n"), false);
      std::string minGoRatePct = trim(readLine("Minimum GO rate percent (0-100)", "0"));
      bool showDetails = parseYesNo(readLine("Show per-run details? (Y/n)", "y"), true);
      std::string showTopReasons = trim(readLine("Show top no-go reasons (count)", "5"));
      std::string summaryJson = trim(readLine("Summary JSON output path (optional)", ""));
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON payload to console? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-quick-trend"
          << " --max-reports " << shellEscape(maxReports)
          << " --since-hours " << shellEscape(sinceHours)
          << " --require-status-ok " << (requireStatusOk ? "1" : "0")
          << " --require-runbook-ok " << (requireRunbookOk ? "1" : "0")
          << " --require-signoff-attempted " << (requireSignoffAttempted ? "1" : "0")
          << " --require-signoff-ok " << (requireSignoffOk ? "1" : "0")
          << " --require-cohort-signoff-policy " << (requireCohortSignoffPolicy ? "1" : "0")
          << " --require-summary-json " << (requireSummaryJson ? "1" : "0")
          << " --require-summary-status-ok " << (requireSummaryStatusOk ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireIncidentSnapshotOnFail ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireIncidentSnapshotArtifacts ? "1" : "0")
          << " --max-duration-sec " << shellEscape(maxDurationSec)
          << " --fail-on-any-no-go " << (failOnAnyNoGo ? "1" : "0")
          << " --min-go-rate-pct " << shellEscape(minGoRatePct)
          << " --show-details " << (showDetails ? "1" : "0")
          << " --show-top-reasons " << shellEscape(showTopReasons)
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "55") {
      bool useTrendSummary = parseYesNo(readLine("Use existing quick trend summary JSON file? (y/N)", "n"), false);
      std::string trendSummaryJson;
      std::string reportsDir;
      std::string maxReports = "25";
      std::string sinceHours = "24";
      bool requireStatusOk = true;
      bool requireRunbookOk = true;
      bool requireSignoffAttempted = true;
      bool requireSignoffOk = true;
      bool requireCohortSignoffPolicy = true;
      bool requireSummaryJson = true;
      bool requireSummaryStatusOk = true;
      bool requireIncidentSnapshotOnFail = true;
      bool requireIncidentSnapshotArtifacts = true;
      std::string maxDurationSec = "0";

      if (useTrendSummary) {
        trendSummaryJson = trim(readLine("Quick trend summary JSON path", ".easy-node-logs/prod_pilot_quick_trend_24h.json"));
      } else {
        reportsDir = trim(readLine("Reports directory (scan for quick run reports)", ".easy-node-logs"));
        maxReports = trim(readLine("Max reports to evaluate", "25"));
        sinceHours = trim(readLine("Include only reports from last N hours (0=all)", "24"));
        requireStatusOk = parseYesNo(readLine("Require quick status=ok? (Y/n)", "y"), true);
        requireRunbookOk = parseYesNo(readLine("Require runbook rc=0? (Y/n)", "y"), true);
        requireSignoffAttempted = parseYesNo(readLine("Require signoff attempted=true? (Y/n)", "y"), true);
        requireSignoffOk = parseYesNo(readLine("Require signoff rc=0? (Y/n)", "y"), true);
        requireCohortSignoffPolicy = parseYesNo(readLine("Re-validate strict cohort signoff policy? (Y/n)", "y"), true);
        requireSummaryJson = parseYesNo(readLine("Require summary JSON artifact exists? (Y/n)", "y"), true);
        requireSummaryStatusOk = parseYesNo(readLine("Require summary status=ok? (Y/n)", "y"), true);
        maxDurationSec = trim(readLine("Max duration sec (0=disabled)", "0"));
      }

      std::string warnGoRatePct = trim(readLine("WARN when GO rate below percent", "98"));
      std::string criticalGoRatePct = trim(readLine("CRITICAL when GO rate below percent", "90"));
      std::string warnNoGoCount = trim(readLine("WARN when NO-GO count >=", "1"));
      std::string criticalNoGoCount = trim(readLine("CRITICAL when NO-GO count >=", "2"));
      std::string warnEvalErrors = trim(readLine("WARN when evaluation errors >=", "1"));
      std::string criticalEvalErrors = trim(readLine("CRITICAL when evaluation errors >=", "2"));
      bool failOnWarn = parseYesNo(readLine("Return non-zero on WARN? (y/N)", "n"), false);
      bool failOnCritical = parseYesNo(readLine("Return non-zero on CRITICAL? (y/N)", "n"), false);
      std::string showTopReasons = trim(readLine("Top no-go reasons to include", "5"));
      std::string summaryJson = trim(readLine("Alert summary JSON output path (optional)", ""));
      bool printSummaryJson = parseYesNo(readLine("Print alert summary JSON payload to console? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-quick-alert"
          << " --warn-go-rate-pct " << shellEscape(warnGoRatePct)
          << " --critical-go-rate-pct " << shellEscape(criticalGoRatePct)
          << " --warn-no-go-count " << shellEscape(warnNoGoCount)
          << " --critical-no-go-count " << shellEscape(criticalNoGoCount)
          << " --warn-eval-errors " << shellEscape(warnEvalErrors)
          << " --critical-eval-errors " << shellEscape(criticalEvalErrors)
          << " --fail-on-warn " << (failOnWarn ? "1" : "0")
          << " --fail-on-critical " << (failOnCritical ? "1" : "0")
          << " --show-top-reasons " << shellEscape(showTopReasons)
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");

      if (useTrendSummary) {
        if (!trendSummaryJson.empty()) {
          cmd << " --trend-summary-json " << shellEscape(trendSummaryJson);
        }
      } else {
        if (!reportsDir.empty()) {
          cmd << " --reports-dir " << shellEscape(reportsDir);
        }
        cmd << " --max-reports " << shellEscape(maxReports)
            << " --since-hours " << shellEscape(sinceHours)
            << " --require-status-ok " << (requireStatusOk ? "1" : "0")
            << " --require-runbook-ok " << (requireRunbookOk ? "1" : "0")
            << " --require-signoff-attempted " << (requireSignoffAttempted ? "1" : "0")
            << " --require-signoff-ok " << (requireSignoffOk ? "1" : "0")
            << " --require-cohort-signoff-policy " << (requireCohortSignoffPolicy ? "1" : "0")
            << " --require-summary-json " << (requireSummaryJson ? "1" : "0")
            << " --require-summary-status-ok " << (requireSummaryStatusOk ? "1" : "0")
            << " --require-incident-snapshot-on-fail " << (requireIncidentSnapshotOnFail ? "1" : "0")
            << " --require-incident-snapshot-artifacts " << (requireIncidentSnapshotArtifacts ? "1" : "0")
            << " --max-duration-sec " << shellEscape(maxDurationSec);
      }
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "56") {
      std::string reportsDir = trim(readLine("Reports directory (scan for quick run reports)", ".easy-node-logs"));
      std::string maxReports = trim(readLine("Max reports to evaluate", "25"));
      std::string sinceHours = trim(readLine("Include only reports from last N hours (0=all)", "24"));
      bool requireStatusOk = parseYesNo(readLine("Require quick status=ok? (Y/n)", "y"), true);
      bool requireRunbookOk = parseYesNo(readLine("Require runbook rc=0? (Y/n)", "y"), true);
      bool requireSignoffAttempted = parseYesNo(readLine("Require signoff attempted=true? (Y/n)", "y"), true);
      bool requireSignoffOk = parseYesNo(readLine("Require signoff rc=0? (Y/n)", "y"), true);
      bool requireCohortSignoffPolicy = parseYesNo(readLine("Re-validate strict cohort signoff policy? (Y/n)", "y"), true);
      bool requireSummaryJson = parseYesNo(readLine("Require summary JSON artifact exists? (Y/n)", "y"), true);
      bool requireSummaryStatusOk = parseYesNo(readLine("Require summary status=ok? (Y/n)", "y"), true);
      bool requireIncidentSnapshotOnFail = true;
      bool requireIncidentSnapshotArtifacts = true;
      std::string maxDurationSec = trim(readLine("Max duration sec (0=disabled)", "0"));
      bool failOnAnyNoGo = parseYesNo(readLine("Fail if any run is NO-GO? (y/N)", "n"), false);
      std::string minGoRatePct = trim(readLine("Minimum GO rate percent (0-100)", "95"));
      std::string showTopReasons = trim(readLine("Top no-go reasons to include", "5"));

      std::string warnGoRatePct = trim(readLine("WARN when GO rate below percent", "98"));
      std::string criticalGoRatePct = trim(readLine("CRITICAL when GO rate below percent", "90"));
      std::string warnNoGoCount = trim(readLine("WARN when NO-GO count >=", "1"));
      std::string criticalNoGoCount = trim(readLine("CRITICAL when NO-GO count >=", "2"));
      std::string warnEvalErrors = trim(readLine("WARN when evaluation errors >=", "1"));
      std::string criticalEvalErrors = trim(readLine("CRITICAL when evaluation errors >=", "2"));
      bool failOnWarn = parseYesNo(readLine("Return non-zero on WARN? (y/N)", "n"), false);
      bool failOnCritical = parseYesNo(readLine("Return non-zero on CRITICAL? (y/N)", "n"), false);

      std::string trendSummaryJson = trim(readLine("Quick trend summary JSON output path (optional)", ".easy-node-logs/prod_pilot_quick_trend_24h.json"));
      std::string alertSummaryJson = trim(readLine("Quick alert summary JSON output path (optional)", ".easy-node-logs/prod_pilot_quick_alert_24h.json"));
      std::string dashboardMd = trim(readLine("Quick dashboard markdown output path (optional)", ".easy-node-logs/prod_pilot_quick_dashboard_24h.md"));
      bool printDashboard = parseYesNo(readLine("Print dashboard markdown after generation? (Y/n)", "y"), true);
      bool printSummaryJson = parseYesNo(readLine("Print trend/alert JSON payloads to console? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-quick-dashboard"
          << " --max-reports " << shellEscape(maxReports)
          << " --since-hours " << shellEscape(sinceHours)
          << " --require-status-ok " << (requireStatusOk ? "1" : "0")
          << " --require-runbook-ok " << (requireRunbookOk ? "1" : "0")
          << " --require-signoff-attempted " << (requireSignoffAttempted ? "1" : "0")
          << " --require-signoff-ok " << (requireSignoffOk ? "1" : "0")
          << " --require-cohort-signoff-policy " << (requireCohortSignoffPolicy ? "1" : "0")
          << " --require-summary-json " << (requireSummaryJson ? "1" : "0")
          << " --require-summary-status-ok " << (requireSummaryStatusOk ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireIncidentSnapshotOnFail ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireIncidentSnapshotArtifacts ? "1" : "0")
          << " --max-duration-sec " << shellEscape(maxDurationSec)
          << " --fail-on-any-no-go " << (failOnAnyNoGo ? "1" : "0")
          << " --min-go-rate-pct " << shellEscape(minGoRatePct)
          << " --show-top-reasons " << shellEscape(showTopReasons)
          << " --warn-go-rate-pct " << shellEscape(warnGoRatePct)
          << " --critical-go-rate-pct " << shellEscape(criticalGoRatePct)
          << " --warn-no-go-count " << shellEscape(warnNoGoCount)
          << " --critical-no-go-count " << shellEscape(criticalNoGoCount)
          << " --warn-eval-errors " << shellEscape(warnEvalErrors)
          << " --critical-eval-errors " << shellEscape(criticalEvalErrors)
          << " --fail-on-warn " << (failOnWarn ? "1" : "0")
          << " --fail-on-critical " << (failOnCritical ? "1" : "0")
          << " --print-dashboard " << (printDashboard ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!trendSummaryJson.empty()) {
        cmd << " --trend-summary-json " << shellEscape(trendSummaryJson);
      }
      if (!alertSummaryJson.empty()) {
        cmd << " --alert-summary-json " << shellEscape(alertSummaryJson);
      }
      if (!dashboardMd.empty()) {
        cmd << " --dashboard-md " << shellEscape(dashboardMd);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "57") {
      std::string runReportJson = trim(readLine("Quick run report JSON path (recommended)", ".easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_quick_report.json"));
      std::string reportsDir = trim(readLine("Reports directory", ".easy-node-logs"));
      bool checkLatest = parseYesNo(readLine("Run latest quick-check stage? (Y/n)", "y"), true);
      bool checkTrend = parseYesNo(readLine("Run quick-trend stage? (Y/n)", "y"), true);
      bool checkAlert = parseYesNo(readLine("Run quick-alert stage? (Y/n)", "y"), true);
      bool requireStatusOk = parseYesNo(readLine("Require quick status=ok? (Y/n)", "y"), true);
      bool requireRunbookOk = parseYesNo(readLine("Require runbook rc=0? (Y/n)", "y"), true);
      bool requireSignoffAttempted = parseYesNo(readLine("Require signoff attempted=true? (Y/n)", "y"), true);
      bool requireSignoffOk = parseYesNo(readLine("Require signoff rc=0? (Y/n)", "y"), true);
      bool requireCohortSignoffPolicy = parseYesNo(readLine("Re-validate strict cohort signoff policy? (Y/n)", "y"), true);
      bool requireSummaryJson = parseYesNo(readLine("Require summary JSON artifact exists? (Y/n)", "y"), true);
      bool requireSummaryStatusOk = parseYesNo(readLine("Require summary status=ok? (Y/n)", "y"), true);
      bool requireIncidentSnapshotOnFail = true;
      bool requireIncidentSnapshotArtifacts = true;
      std::string maxDurationSec = trim(readLine("Max duration sec (0=disabled)", "0"));
      std::string maxReports = trim(readLine("Max reports to evaluate", "25"));
      std::string sinceHours = trim(readLine("Include only reports from last N hours (0=all)", "24"));
      bool failOnAnyNoGo = parseYesNo(readLine("Fail if any run is NO-GO? (y/N)", "n"), false);
      std::string minGoRatePct = trim(readLine("Minimum GO rate percent (0-100)", "95"));
      std::string warnGoRatePct = trim(readLine("WARN when GO rate below percent", "98"));
      std::string criticalGoRatePct = trim(readLine("CRITICAL when GO rate below percent", "90"));
      std::string warnNoGoCount = trim(readLine("WARN when NO-GO count >=", "1"));
      std::string criticalNoGoCount = trim(readLine("CRITICAL when NO-GO count >=", "2"));
      std::string warnEvalErrors = trim(readLine("WARN when evaluation errors >=", "1"));
      std::string criticalEvalErrors = trim(readLine("CRITICAL when evaluation errors >=", "2"));
      std::string maxAlertSeverity = trim(readLine("Max alert severity allowed (OK/WARN/CRITICAL)", "WARN"));
      std::string maxAlertSeverityUpper = upperCopy(maxAlertSeverity);
      if (maxAlertSeverityUpper != "OK" && maxAlertSeverityUpper != "WARN" && maxAlertSeverityUpper != "CRITICAL") {
        std::cout << "invalid max alert severity; using WARN\n";
        maxAlertSeverityUpper = "WARN";
      }
      std::string trendSummaryJson = trim(readLine("Trend summary JSON output path (optional)", ".easy-node-logs/prod_pilot_quick_signoff_trend.json"));
      std::string alertSummaryJson = trim(readLine("Alert summary JSON output path (optional)", ".easy-node-logs/prod_pilot_quick_signoff_alert.json"));
      std::string signoffJson = trim(readLine("Signoff JSON output path (optional)", ".easy-node-logs/prod_pilot_quick_signoff.json"));
      bool showJson = parseYesNo(readLine("Show signoff JSON payload? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-quick-signoff"
          << " --check-latest " << (checkLatest ? "1" : "0")
          << " --check-trend " << (checkTrend ? "1" : "0")
          << " --check-alert " << (checkAlert ? "1" : "0")
          << " --require-status-ok " << (requireStatusOk ? "1" : "0")
          << " --require-runbook-ok " << (requireRunbookOk ? "1" : "0")
          << " --require-signoff-attempted " << (requireSignoffAttempted ? "1" : "0")
          << " --require-signoff-ok " << (requireSignoffOk ? "1" : "0")
          << " --require-cohort-signoff-policy " << (requireCohortSignoffPolicy ? "1" : "0")
          << " --require-trend-artifact-policy-match 1"
          << " --require-trend-wg-validate-udp-source 1"
          << " --require-trend-wg-validate-strict-distinct 1"
          << " --require-trend-wg-soak-diversity-pass 1"
          << " --min-trend-wg-soak-selection-lines 12"
          << " --min-trend-wg-soak-entry-operators 2"
          << " --min-trend-wg-soak-exit-operators 2"
          << " --min-trend-wg-soak-cross-operator-pairs 2"
          << " --require-bundle-created 1"
          << " --require-bundle-manifest 1"
          << " --require-summary-json " << (requireSummaryJson ? "1" : "0")
          << " --require-summary-status-ok " << (requireSummaryStatusOk ? "1" : "0")
          << " --require-incident-snapshot-on-fail " << (requireIncidentSnapshotOnFail ? "1" : "0")
          << " --require-incident-snapshot-artifacts " << (requireIncidentSnapshotArtifacts ? "1" : "0")
          << " --max-duration-sec " << shellEscape(maxDurationSec)
          << " --max-reports " << shellEscape(maxReports)
          << " --since-hours " << shellEscape(sinceHours)
          << " --fail-on-any-no-go " << (failOnAnyNoGo ? "1" : "0")
          << " --min-go-rate-pct " << shellEscape(minGoRatePct)
          << " --warn-go-rate-pct " << shellEscape(warnGoRatePct)
          << " --critical-go-rate-pct " << shellEscape(criticalGoRatePct)
          << " --warn-no-go-count " << shellEscape(warnNoGoCount)
          << " --critical-no-go-count " << shellEscape(criticalNoGoCount)
          << " --warn-eval-errors " << shellEscape(warnEvalErrors)
          << " --critical-eval-errors " << shellEscape(criticalEvalErrors)
          << " --max-alert-severity " << shellEscape(maxAlertSeverityUpper)
          << " --show-json " << (showJson ? "1" : "0");
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson);
      }
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!trendSummaryJson.empty()) {
        cmd << " --trend-summary-json " << shellEscape(trendSummaryJson);
      }
      if (!alertSummaryJson.empty()) {
        cmd << " --alert-summary-json " << shellEscape(alertSummaryJson);
      }
      if (!signoffJson.empty()) {
        cmd << " --signoff-json " << shellEscape(signoffJson);
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "58") {
      std::string bootstrapDefault = endpointFromHost(hosts.aHost, 8081);
      std::string bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
      std::string subject = trim(readLine("Client subject/invite key", "pilot-client"));
      std::string rounds = trim(readLine("Cohort rounds", "5"));
      std::string pauseSec = trim(readLine("Pause between rounds (sec)", "60"));
      bool continueOnFail = parseYesNo(readLine("Continue running after a failed round? (y/N)", "n"), false);
      bool requireAllRoundsOk = parseYesNo(readLine("Require all rounds to pass? (Y/n)", "y"), true);
      std::string maxRoundFailures = trim(readLine("Max failed rounds allowed for signoff", "0"));
      std::string trendMinGoRate = trim(readLine("Minimum GO rate percent", "95"));
      std::string maxAlertSeverity = trim(readLine("Max alert severity allowed (OK/WARN/CRITICAL)", "WARN"));
      std::string maxAlertSeverityUpper = upperCopy(maxAlertSeverity);
      if (maxAlertSeverityUpper != "OK" && maxAlertSeverityUpper != "WARN" && maxAlertSeverityUpper != "CRITICAL") {
        std::cout << "invalid max alert severity; using WARN\n";
        maxAlertSeverityUpper = "WARN";
      }
      bool bundleOutputs = parseYesNo(readLine("Require bundle outputs in quick run/signoff? (Y/n)", "y"), true);
      bool bundleFailClose = parseYesNo(readLine("Fail if bundle generation stage fails? (Y/n)", "y"), true);
      std::string reportsDir = trim(readLine("Reports directory", ".easy-node-logs/prod_pilot_cohort_quick_runbook"));
      std::string summaryJson = trim(readLine("Cohort summary JSON path (optional)", ""));
      std::string runReportJson = trim(readLine("Quick run report JSON path (optional)", ""));
      std::string signoffJson = trim(readLine("Quick signoff JSON path (optional)", ""));
      std::string trendSummaryJson = trim(readLine("Quick trend summary JSON path (optional)", ""));
      std::string alertSummaryJson = trim(readLine("Quick alert summary JSON path (optional)", ""));
      std::string dashboardMd = trim(readLine("Quick dashboard markdown path (optional)", ""));
      std::string signoffMaxReports = trim(readLine("Signoff trend max reports", "25"));
      std::string signoffSinceHours = trim(readLine("Signoff trend since hours", "24"));
      bool signoffFailOnAnyNoGo = parseYesNo(readLine("Signoff fail on any NO-GO trend? (y/N)", "n"), false);
      std::string signoffMinGoRate = trim(readLine("Signoff minimum GO rate percent", "95"));
      bool signoffRequireCohortSignoffPolicy = parseYesNo(readLine("Signoff re-validates strict cohort policy? (Y/n)", "y"), true);
      bool signoffRequireIncidentSnapshotOnFail = true;
      bool signoffRequireIncidentSnapshotArtifacts = true;
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness once before the cohort? (Y/n)", "y"), true);
      bool dashboardEnable = parseYesNo(readLine("Generate quick dashboard artifacts? (Y/n)", "y"), true);
      bool dashboardFailClose = parseYesNo(readLine("Fail run if dashboard stage fails? (y/N)", "n"), false);
      bool dashboardPrint = parseYesNo(readLine("Print dashboard markdown? (Y/n)", "y"), true);
      bool dashboardPrintSummaryJson = parseYesNo(readLine("Print dashboard trend/alert JSON payloads? (y/N)", "n"), false);
      bool showJson = parseYesNo(readLine("Show runbook summary JSON payload? (y/N)", "n"), false);
      std::string extraArgs = trim(readLine("Extra prod-pilot-runbook args after '--' (optional)", ""));

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-quick-runbook"
          << " --bootstrap-directory " << shellEscape(bootstrapDir)
          << " --subject " << shellEscape(subject)
          << " --rounds " << shellEscape(rounds)
          << " --pause-sec " << shellEscape(pauseSec)
          << " --continue-on-fail " << (continueOnFail ? "1" : "0")
          << " --require-all-rounds-ok " << (requireAllRoundsOk ? "1" : "0")
          << " --max-round-failures " << shellEscape(maxRoundFailures)
          << " --trend-min-go-rate-pct " << shellEscape(trendMinGoRate)
          << " --max-alert-severity " << shellEscape(maxAlertSeverityUpper)
          << " --bundle-outputs " << (bundleOutputs ? "1" : "0")
          << " --bundle-fail-close " << (bundleFailClose ? "1" : "0")
          << " --pre-real-host-readiness " << (runPreRealHostReadiness ? "1" : "0")
          << " --reports-dir " << shellEscape(reportsDir)
          << " --signoff-max-reports " << shellEscape(signoffMaxReports)
          << " --signoff-since-hours " << shellEscape(signoffSinceHours)
          << " --signoff-fail-on-any-no-go " << (signoffFailOnAnyNoGo ? "1" : "0")
          << " --signoff-min-go-rate-pct " << shellEscape(signoffMinGoRate)
          << " --signoff-require-cohort-signoff-policy " << (signoffRequireCohortSignoffPolicy ? "1" : "0")
          << " --signoff-require-trend-artifact-policy-match 1"
          << " --signoff-require-trend-wg-validate-udp-source 1"
          << " --signoff-require-trend-wg-validate-strict-distinct 1"
          << " --signoff-require-trend-wg-soak-diversity-pass 1"
          << " --signoff-min-trend-wg-soak-selection-lines 12"
          << " --signoff-min-trend-wg-soak-entry-operators 2"
          << " --signoff-min-trend-wg-soak-exit-operators 2"
          << " --signoff-min-trend-wg-soak-cross-operator-pairs 2"
          << " --signoff-require-incident-snapshot-on-fail " << (signoffRequireIncidentSnapshotOnFail ? "1" : "0")
          << " --signoff-require-incident-snapshot-artifacts " << (signoffRequireIncidentSnapshotArtifacts ? "1" : "0")
          << " --dashboard-enable " << (dashboardEnable ? "1" : "0")
          << " --dashboard-fail-close " << (dashboardFailClose ? "1" : "0")
          << " --dashboard-print " << (dashboardPrint ? "1" : "0")
          << " --dashboard-print-summary-json " << (dashboardPrintSummaryJson ? "1" : "0")
          << " --show-json " << (showJson ? "1" : "0");
      if (!summaryJson.empty()) {
        cmd << " --summary-json " << shellEscape(summaryJson);
      }
      if (!runReportJson.empty()) {
        cmd << " --run-report-json " << shellEscape(runReportJson);
      }
      if (!signoffJson.empty()) {
        cmd << " --signoff-json " << shellEscape(signoffJson);
      }
      if (!trendSummaryJson.empty()) {
        cmd << " --trend-summary-json " << shellEscape(trendSummaryJson);
      }
      if (!alertSummaryJson.empty()) {
        cmd << " --alert-summary-json " << shellEscape(alertSummaryJson);
      }
      if (!dashboardMd.empty()) {
        cmd << " --dashboard-md " << shellEscape(dashboardMd);
      }
      if (!extraArgs.empty()) {
        cmd << " -- " << extraArgs;
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "59") {
      std::string bootstrapDefault = endpointFromHost(hosts.aHost, 8081);
      std::string bootstrapDir = normalizeEndpointURL(readLine("Bootstrap directory URL", bootstrapDefault), 8081);
      std::string subject = trim(readLine("Client subject/invite key", "pilot-client"));
      std::string reportsDir = trim(readLine("Reports directory (optional; blank=timestamped default)", ""));
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness once before the campaign? (Y/n)", "y"), true);
      bool showJson = parseYesNo(readLine("Show campaign summary JSON payload? (y/N)", "n"), false);
      std::string extraArgs = trim(readLine("Extra campaign args (optional)", ""));

      std::ostringstream cmd;
      cmd << shellEscape(script) << " prod-pilot-cohort-campaign"
          << " --bootstrap-directory " << shellEscape(bootstrapDir)
          << " --subject " << shellEscape(subject)
          << " --pre-real-host-readiness " << (runPreRealHostReadiness ? "1" : "0")
          << " --show-json " << (showJson ? "1" : "0");
      if (!reportsDir.empty()) {
        cmd << " --reports-dir " << shellEscape(reportsDir);
      }
      if (!extraArgs.empty()) {
        cmd << " " << extraArgs;
      }
      runCommand(cmd.str());
      continue;
    }
    if (choice == "60") {
      std::string basePort = trim(readLine("WG-only base port", "19280"));
      std::string clientIface = trim(readLine("WG-only client iface", "wgcstack0"));
      std::string exitIface = trim(readLine("WG-only exit iface", "wgestack0"));
      std::string vpnIface = trim(readLine("Client VPN iface", "wgvpn0"));
      bool showJson = parseYesNo(readLine("Show JSON summary payload? (Y/n)", "y"), true);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " runtime-doctor"
          << " --base-port " << shellEscape(basePort)
          << " --client-iface " << shellEscape(clientIface)
          << " --exit-iface " << shellEscape(exitIface)
          << " --vpn-iface " << shellEscape(vpnIface)
          << " --show-json " << (showJson ? "1" : "0");
      runCommand(cmd.str());
      continue;
    }
    if (choice == "61") {
      runCommand(shellEscape(script) + " manual-validation-backlog");
      continue;
    }
    if (choice == "62") {
      std::string basePort = trim(readLine("WG-only base port", "19280"));
      std::string clientIface = trim(readLine("WG-only client iface", "wgcstack0"));
      std::string exitIface = trim(readLine("WG-only exit iface", "wgestack0"));
      std::string vpnIface = trim(readLine("Client VPN iface", "wgvpn0"));
      bool pruneWgOnlyDir = parseYesNo(readLine("Prune wg-only runtime dir after cleanup? (y/N)", "n"), false);
      bool showJson = parseYesNo(readLine("Show JSON summary payload? (Y/n)", "y"), true);
      bool runWithSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);

      std::ostringstream cmd;
      if (runWithSudo) {
        cmd << "sudo ";
      }
      cmd << shellEscape(script) << " runtime-fix"
          << " --base-port " << shellEscape(basePort)
          << " --client-iface " << shellEscape(clientIface)
          << " --exit-iface " << shellEscape(exitIface)
          << " --vpn-iface " << shellEscape(vpnIface)
          << " --prune-wg-only-dir " << (pruneWgOnlyDir ? "1" : "0")
          << " --show-json " << (showJson ? "1" : "0");
      runCommand(cmd.str());
      continue;
    }
    if (choice == "63") {
      std::string basePort = trim(readLine("WG-only base port", "19280"));
      std::string clientIface = trim(readLine("WG-only client iface", "wgcstack0"));
      std::string exitIface = trim(readLine("WG-only exit iface", "wgestack0"));
      std::string vpnIface = trim(readLine("Client VPN iface", "wgvpn0"));
      bool showJson = parseYesNo(readLine("Show JSON summary payload? (Y/n)", "y"), true);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " manual-validation-status"
          << " --base-port " << shellEscape(basePort)
          << " --client-iface " << shellEscape(clientIface)
          << " --exit-iface " << shellEscape(exitIface)
          << " --vpn-iface " << shellEscape(vpnIface)
          << " --show-json " << (showJson ? "1" : "0");
      runCommand(cmd.str());
      continue;
    }
    if (choice == "64") {
      std::string bootstrapDir = trim(readLine("Bootstrap directory", "http://198.51.100.10:8081"));
      std::string subject = trim(readLine("Invite key / subject", "pilot-client"));
      std::string interfaceName = trim(readLine("VPN interface", "wgvpn0"));
      std::string publicIpUrl = trim(readLine("Public IP check URL", "https://api.ipify.org"));
      std::string countryUrl = trim(readLine("Country check URL", "https://ipinfo.io/country"));
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness first? (Y/n)", "y"), true);
      bool runRuntimeDoctor = parseYesNo(readLine("Run runtime doctor first? (Y/n)", "y"), true);
      bool autoRuntimeFix = parseYesNo(readLine("Auto-apply runtime fix if needed? (y/N)", "n"), false);
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON? (y/N)", "n"), false);
      bool runWithSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);

      std::ostringstream cmd;
      if (runWithSudo) {
        cmd << "sudo ";
      }
      cmd << shellEscape(script) << " client-vpn-smoke"
          << " --bootstrap-directory " << shellEscape(bootstrapDir)
          << " --subject " << shellEscape(subject)
          << " --beta-profile 1"
          << " --path-profile balanced"
          << " --distinct-operators 1"
          << " --interface " << shellEscape(interfaceName)
          << " --pre-real-host-readiness " << (runPreRealHostReadiness ? "1" : "0")
          << " --runtime-doctor " << (runRuntimeDoctor ? "1" : "0")
          << " --runtime-fix " << (autoRuntimeFix ? "1" : "0")
          << " --public-ip-url " << shellEscape(publicIpUrl)
          << " --country-url " << shellEscape(countryUrl)
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      runCommand(cmd.str());
      continue;
    }
    if (choice == "65") {
      std::string directoryA = trim(readLine("Directory A URL", "https://" + hosts.aHost + ":8081"));
      std::string directoryB = trim(readLine("Directory B URL", "https://" + hosts.bHost + ":8081"));
      std::string issuerUrl = trim(readLine("Issuer URL", "https://" + hosts.aHost + ":8082"));
      std::string entryUrl = trim(readLine("Entry URL", "https://" + hosts.aHost + ":8083"));
      std::string exitUrl = trim(readLine("Exit URL", "https://" + hosts.bHost + ":8084"));
      std::string bundleDir = trim(readLine("Bundle dir", ".easy-node-logs/prod_gate_bundle"));
      bool runPreRealHostReadiness = parseYesNo(readLine("Run pre-real-host readiness first? (Y/n)", "y"), true);
      bool runRuntimeDoctor = parseYesNo(readLine("Run runtime doctor first? (Y/n)", "y"), true);
      bool autoRuntimeFix = parseYesNo(readLine("Auto-apply runtime fix if needed? (y/N)", "n"), false);
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON? (y/N)", "n"), false);
      bool runWithSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);

      std::ostringstream cmd;
      if (runWithSudo) {
        cmd << "sudo ";
      }
      cmd << shellEscape(script) << " three-machine-prod-signoff"
          << " --directory-a " << shellEscape(directoryA)
          << " --directory-b " << shellEscape(directoryB)
          << " --issuer-url " << shellEscape(issuerUrl)
          << " --entry-url " << shellEscape(entryUrl)
          << " --exit-url " << shellEscape(exitUrl)
          << " --bundle-dir " << shellEscape(bundleDir)
          << " --pre-real-host-readiness " << (runPreRealHostReadiness ? "1" : "0")
          << " --runtime-doctor " << (runRuntimeDoctor ? "1" : "0")
          << " --runtime-fix " << (autoRuntimeFix ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      runCommand(cmd.str());
      continue;
    }
    if (choice == "66") {
      std::string basePort = trim(readLine("WG-only base port", "19280"));
      std::string clientIface = trim(readLine("WG-only client iface", "wgcstack0"));
      std::string exitIface = trim(readLine("WG-only exit iface", "wgestack0"));
      std::string vpnIface = trim(readLine("Client VPN iface", "wgvpn0"));
      std::string summaryJson = trim(readLine("Summary JSON path", ".easy-node-logs/manual_validation_readiness_summary.json"));
      std::string reportMd = trim(readLine("Report markdown path", ".easy-node-logs/manual_validation_readiness_report.md"));
      bool printReport = parseYesNo(readLine("Print markdown report? (Y/n)", "y"), true);
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON? (y/N)", "n"), false);
      bool failOnNotReady = parseYesNo(readLine("Fail if readiness is not complete? (y/N)", "n"), false);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " manual-validation-report"
          << " --base-port " << shellEscape(basePort)
          << " --client-iface " << shellEscape(clientIface)
          << " --exit-iface " << shellEscape(exitIface)
          << " --vpn-iface " << shellEscape(vpnIface)
          << " --summary-json " << shellEscape(summaryJson)
          << " --report-md " << shellEscape(reportMd)
          << " --print-report " << (printReport ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0")
          << " --fail-on-not-ready " << (failOnNotReady ? "1" : "0");
      runCommand(cmd.str());
      printManualValidationReportSummary(resolveRepoPath(root, summaryJson));
      continue;
    }
    if (choice == "67") {
      std::string basePort = trim(readLine("WG-only base port", "19280"));
      std::string clientIface = trim(readLine("WG-only client iface", "wgcstack0"));
      std::string exitIface = trim(readLine("WG-only exit iface", "wgestack0"));
      bool strictBeta = parseYesNo(readLine("Use strict beta profile? (Y/n)", "y"), true);
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON? (y/N)", "n"), false);
      bool runWithSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);

      std::ostringstream cmd;
      if (runWithSudo) {
        cmd << "sudo ";
      }
      cmd << shellEscape(script) << " wg-only-stack-selftest-record"
          << " --base-port " << shellEscape(basePort)
          << " --client-iface " << shellEscape(clientIface)
          << " --exit-iface " << shellEscape(exitIface)
          << " --strict-beta " << (strictBeta ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      runCommand(cmd.str());
      continue;
    }
    if (choice == "68") {
      std::string basePort = trim(readLine("WG-only base port", "19280"));
      std::string clientIface = trim(readLine("WG-only client iface", "wgcstack0"));
      std::string exitIface = trim(readLine("WG-only exit iface", "wgestack0"));
      std::string vpnIface = trim(readLine("Client VPN iface", "wgvpn0"));
      bool pruneWgOnlyDir = parseYesNo(readLine("Prune wg-only runtime dir during cleanup? (Y/n)", "y"), true);
      bool strictBeta = parseYesNo(readLine("Use strict beta profile? (Y/n)", "y"), true);
      bool printSummaryJson = parseYesNo(readLine("Print summary JSON? (y/N)", "n"), false);
      bool runWithSudo = parseYesNo(readLine("Run with sudo? (Y/n)", "y"), true);

      std::ostringstream cmd;
      if (runWithSudo) {
        cmd << "sudo ";
      }
      cmd << shellEscape(script) << " pre-real-host-readiness"
          << " --base-port " << shellEscape(basePort)
          << " --client-iface " << shellEscape(clientIface)
          << " --exit-iface " << shellEscape(exitIface)
          << " --vpn-iface " << shellEscape(vpnIface)
          << " --runtime-fix-prune-wg-only-dir " << (pruneWgOnlyDir ? "1" : "0")
          << " --strict-beta " << (strictBeta ? "1" : "0")
          << " --print-summary-json " << (printSummaryJson ? "1" : "0");
      runCommand(cmd.str());
      printManualValidationReportSummary(resolveRepoPath(root, ".easy-node-logs/manual_validation_readiness_summary.json"));
      continue;
    }

    std::cout << "invalid selection\n";
  }
}

} // namespace

int main() {
  std::string root = detectRepoRoot();
  if (root.empty()) {
    std::cerr << "could not detect repo root; run from repo root or set PRIVACYNODE_ROOT\n";
    return 1;
  }

  std::filesystem::path scriptPath = std::filesystem::path(root) / "scripts" / "easy_node.sh";
  if (!std::filesystem::exists(scriptPath)) {
    std::cerr << "missing script: " << scriptPath << "\n";
    return 1;
  }

  const std::string script = scriptPath.string();
  ABHosts hosts = loadABHosts(root);

  std::cout << "Privacynode Easy Launcher\n";
  std::cout << "repo: " << root << "\n";

  for (;;) {
    std::cout << "\nMain menu:\n";
    std::cout << "1) Connect as CLIENT (simple)\n";
    std::cout << "2) Connect as SERVER (simple, provider default)\n";
    std::cout << "3) Other options (tests/config)\n";
    std::cout << "0) Exit\n";
    std::cout << "Selection: ";

    std::string choice;
    std::getline(std::cin, choice);
    choice = trim(choice);

    if (choice == "0") {
      return 0;
    }
    if (choice == "1") {
      quickClientConnect(script, hosts);
      continue;
    }
    if (choice == "2") {
      quickServerConnect(root, script, hosts);
      continue;
    }
    if (choice == "3") {
      runAdvancedMenu(root, script, hosts);
      continue;
    }
    std::cout << "invalid selection\n";
  }
}
