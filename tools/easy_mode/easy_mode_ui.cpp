#include <cstdlib>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

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

int runCommand(const std::string &cmd) {
  std::cout << "\n$ " << cmd << "\n\n" << std::flush;
  int rc = std::system(cmd.c_str());
  if (rc != 0) {
    std::cout << "command failed with code " << rc << "\n";
  }
  return rc;
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

void showThreeMachineGuide() {
  std::cout << "\n3-machine quick flow\n";
  std::cout << "1) Machine A: server-up with A public IP/host and --beta-profile (IDs auto-generated)\n";
  std::cout << "2) Machine B: server-up with B public IP/host, --peer-directories=http://A:8081 and --beta-profile\n";
  std::cout << "3) Machine A (optional): rerun server-up with --peer-directories=http://B:8081\n";
  std::cout << "4) Machine C: client-test with --directory-urls=http://A:8081,http://B:8081 --beta-profile --distinct-operators\n";
  std::cout << "5) One-IP mode: use machine-C bootstrap discovery from one known directory URL\n";
  std::cout << "6) Success signal: client log contains 'client selected entry='\n\n";
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
      bool distinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", betaProfile ? "y" : "n"), betaProfile);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
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
      bool distinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", betaProfile ? "y" : "n"), betaProfile);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
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
  std::string timeoutSec = readLine("Connection timeout sec", "45");
  std::string discoveryWait = readLine("Discovery wait sec", "12");
  bool prodProfile = parseYesNo(readLine("Use PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
  if (bootstrapDir.empty()) {
    std::cout << "server IP/host is required\n";
    return;
  }
  if (inviteKey.empty()) {
    std::cout << "invite key is required\n";
    return;
  }
  std::ostringstream cmd;
  cmd << shellEscape(script) << " client-test"
      << " --bootstrap-directory " << shellEscape(bootstrapDir)
      << " --discovery-wait-sec " << shellEscape(discoveryWait)
      << " --subject " << shellEscape(inviteKey)
      << " --min-sources 1"
      << " --timeout-sec " << shellEscape(timeoutSec)
      << " --beta-profile 1"
      << " --prod-profile " << (prodProfile ? "1" : "0")
      << " --distinct-operators 1";
  runCommand(cmd.str());
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
  std::string peerHost = normalizePublicHostInput(readLine("Peer server IP/host (optional)", peerDefault));
  if (host.empty()) {
    std::cout << "public host/IP is required\n";
    return;
  }
  bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);

  std::ostringstream cmd;
  cmd << shellEscape(script) << " server-up"
      << " --mode " << (authorityMode ? "authority" : "provider")
      << " --public-host " << shellEscape(host)
      << " --beta-profile 1"
      << " --prod-profile " << (prodProfile ? "1" : "0");
  if (authorityMode) {
    cmd << " --client-allowlist 1"
        << " --allow-anon-cred 0";
    if (!peerHost.empty()) {
      cmd << " --peer-directories " << shellEscape(endpointFromHost(peerHost, 8081));
    }
  } else {
    std::string authorityDirDefault = !peerHost.empty() ? endpointFromHost(peerHost, 8081) : "";
    std::string authorityDir = normalizeEndpointURL(readLine("Authority directory URL", authorityDirDefault), 8081);
    std::string authorityIssuerDefault = "";
    if (!authorityDir.empty()) {
      std::string authorityHost = normalizePublicHostInput(authorityDir);
      authorityHost = stripSchemeAndPath(authorityHost);
      if (!authorityHost.empty()) {
        authorityIssuerDefault = endpointFromHost(normalizePublicHostInput(authorityHost), 8082);
      }
    }
    std::string authorityIssuer = normalizeEndpointURL(readLine("Authority issuer URL", authorityIssuerDefault), 8082);
    if (authorityDir.empty() || authorityIssuer.empty()) {
      std::cout << "authority directory and issuer URLs are required for provider mode\n";
      return;
    }
    cmd << " --authority-directory " << shellEscape(authorityDir)
        << " --authority-issuer " << shellEscape(authorityIssuer)
        << " --peer-directories " << shellEscape(authorityDir);
  }
  int rc = runCommand(cmd.str());

  bool saveHosts = parseYesNo(readLine("Save/update Machine A/B host config? (y/N)", "n"), false);
  if (saveHosts) {
    configureABHostsInteractive(root, hosts, true);
  }

  if (rc == 0 && authorityMode) {
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
      std::string adminToken = trim(readLine("Admin token (optional; blank=read from server env)", ""));
      std::ostringstream cmd;
      cmd << shellEscape(script) << " invite-generate"
          << " --count " << shellEscape(count)
          << " --prefix " << shellEscape(prefix)
          << " --tier " << shellEscape(tier);
      if (!issuer.empty()) {
        cmd << " --issuer-url " << shellEscape(issuer);
      }
      if (!adminToken.empty()) {
        cmd << " --admin-token " << shellEscape(adminToken);
      }
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
      std::string adminToken = trim(readLine("Admin token (optional; blank=read from server env)", ""));
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
      if (!adminToken.empty()) {
        cmd << " --admin-token " << shellEscape(adminToken);
      }
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
      std::string adminToken = trim(readLine("Admin token (optional; blank=read from server env)", ""));
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
      if (!adminToken.empty()) {
        cmd << " --admin-token " << shellEscape(adminToken);
      }
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
      bool distinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", betaProfile ? "y" : "n"), betaProfile);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
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
      bool distinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", betaProfile ? "y" : "n"), betaProfile);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
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
      bool distinct = parseYesNo(readLine("Require distinct entry/exit operators? (Y/n)", betaProfile ? "y" : "n"), betaProfile);
      bool prodProfile = parseYesNo(readLine("Enable PROD profile (mTLS + strict fail-closed)? (y/N)", "n"), false);
      if (prodProfile) {
        betaProfile = true;
        distinct = true;
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
