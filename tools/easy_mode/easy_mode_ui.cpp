#include <cstdlib>
#include <cctype>
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
  std::cout << "1) Machine A: server-up with A public IP/host\n";
  std::cout << "2) Machine B: server-up with B public IP/host and --peer-directories=http://A:8081\n";
  std::cout << "3) Machine A (optional): rerun server-up with --peer-directories=http://B:8081\n";
  std::cout << "4) Machine C: client-test with --directory-urls=http://A:8081,http://B:8081 and min-sources=2\n";
  std::cout << "5) Success signal: client log contains 'client selected entry='\n\n";
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

std::string normalizeHostInput(const std::string &raw) {
  std::string v = stripSchemeAndPath(raw);
  return trim(v);
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
    std::string v = normalizeHostInput(line.substr(eq + 1));
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
  hosts.aHost = normalizeHostInput(readLine("Machine A IP/host", hosts.aHost));
  hosts.bHost = normalizeHostInput(readLine("Machine B IP/host", hosts.bHost));
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
      std::string host = readLine("Machine A public host/IP (optional)", hosts.aHost);
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
      std::string peerA = readLine("Machine A directory URL", endpointFromHost(hosts.aHost, 8081));
      std::string host = readLine("Machine B public host/IP (optional)", hosts.bHost);
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
      configureABHostsInteractive(root, hosts, false);
      std::string dirA = readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081));
      std::string dirB = readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081));
      std::string issuer = readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082));
      std::string entry = readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083));
      std::string exitUrl = readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084));
      std::string minSources = readLine("Minimum directory sources", "2");
      std::string minOperators = readLine("Minimum operators per directory", "2");
      std::string federationTimeout = readLine("Federation wait timeout sec", "90");
      std::string timeoutSec = readLine("Client validation timeout sec", "50");
      std::string country = readLine("Preferred exit country code (optional)", "");
      std::string region = readLine("Preferred exit region (optional)", "");
      std::string report = readLine("Report file path (optional)", "");
      if (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty()) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }
      std::ostringstream cmd;
      cmd << shellEscape(script) << " machine-c-test"
          << " --directory-a " << shellEscape(dirA)
          << " --directory-b " << shellEscape(dirB)
          << " --issuer-url " << shellEscape(issuer)
          << " --entry-url " << shellEscape(entry)
          << " --exit-url " << shellEscape(exitUrl)
          << " --min-sources " << shellEscape(minSources)
          << " --min-operators " << shellEscape(minOperators)
          << " --federation-timeout-sec " << shellEscape(federationTimeout)
          << " --timeout-sec " << shellEscape(timeoutSec);
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
    std::cout << "\nChoose action:\n";
    std::cout << "1) Check dependencies\n";
    std::cout << "2) Start/update SERVER stack\n";
    std::cout << "3) Client test against remote server(s)\n";
    std::cout << "4) Server status\n";
    std::cout << "5) Server logs\n";
    std::cout << "6) Stop server stack\n";
    std::cout << "7) Show 3-machine test guide\n";
    std::cout << "8) Run 3-machine validation\n";
    std::cout << "9) Run automated tests\n";
    std::cout << "10) Configure machine A/B hosts\n";
    std::cout << "0) Exit\n";
    std::cout << "Selection: ";

    std::string choice;
    std::getline(std::cin, choice);
    choice = trim(choice);

    if (choice == "0") {
      return 0;
    }

    if (choice == "1") {
      runCommand(shellEscape(script) + " check");
      continue;
    }

    if (choice == "2") {
      configureABHostsInteractive(root, hosts, false);
      std::string role = readLine("Server role for this machine (A/B/custom)", "A");
      std::string host;
      std::string peersDefault;
      if (!role.empty() && (role[0] == 'A' || role[0] == 'a')) {
        host = hosts.aHost;
        bool federateWithB = parseYesNo(readLine("Peer with Machine B directory? (y/N)", "n"), false);
        if (federateWithB && !hosts.bHost.empty()) {
          peersDefault = endpointFromHost(hosts.bHost, 8081);
        }
      } else if (!role.empty() && (role[0] == 'B' || role[0] == 'b')) {
        host = hosts.bHost;
        if (!hosts.aHost.empty()) {
          peersDefault = endpointFromHost(hosts.aHost, 8081);
        }
      } else {
        host = readLine("Public host/IP for this server machine (required)");
      }
      host = normalizeHostInput(readLine("Public host/IP for this server machine (required)", host));
      if (host.empty()) {
        std::cout << "host is required\n";
        continue;
      }
      std::string operatorId = readLine("Operator ID", "");
      std::string adminToken = readLine("Issuer admin token (blank=auto)", "");
      std::string peers = readLine("Peer directory URLs CSV (optional, for federation)", peersDefault);

      std::ostringstream cmd;
      cmd << shellEscape(script) << " server-up"
          << " --public-host " << shellEscape(host);
      if (!operatorId.empty()) {
        cmd << " --operator-id " << shellEscape(operatorId);
      }
      if (!adminToken.empty()) {
        cmd << " --issuer-admin-token " << shellEscape(adminToken);
      }
      if (!peers.empty()) {
        cmd << " --peer-directories " << shellEscape(peers);
      }
      runCommand(cmd.str());
      continue;
    }

    if (choice == "3") {
      configureABHostsInteractive(root, hosts, false);
      std::string dirs = readLine("Directory URLs CSV", endpointFromHost(hosts.aHost, 8081) + "," + endpointFromHost(hosts.bHost, 8081));
      std::string issuer = readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082));
      std::string entry = readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083));
      std::string exitUrl = readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084));
      std::string minSources = readLine("Minimum directory sources", "1");
      std::string country = readLine("Preferred exit country code (optional)", "");
      std::string region = readLine("Preferred exit region (optional)", "");
      std::string timeoutSec = readLine("Client test timeout sec", "40");

      if (dirs.empty() || issuer.empty() || entry.empty() || exitUrl.empty()) {
        std::cout << "directory URLs, issuer URL, entry URL and exit URL are required\n";
        continue;
      }

      std::ostringstream cmd;
      cmd << shellEscape(script) << " client-test"
          << " --directory-urls " << shellEscape(dirs)
          << " --issuer-url " << shellEscape(issuer)
          << " --entry-url " << shellEscape(entry)
          << " --exit-url " << shellEscape(exitUrl)
          << " --min-sources " << shellEscape(minSources)
          << " --timeout-sec " << shellEscape(timeoutSec);
      if (!country.empty()) {
        cmd << " --exit-country " << shellEscape(country);
      }
      if (!region.empty()) {
        cmd << " --exit-region " << shellEscape(region);
      }
      runCommand(cmd.str());
      continue;
    }

    if (choice == "4") {
      runCommand(shellEscape(script) + " server-status");
      continue;
    }

    if (choice == "5") {
      runCommand(shellEscape(script) + " server-logs");
      continue;
    }

    if (choice == "6") {
      runCommand(shellEscape(script) + " server-down");
      continue;
    }

    if (choice == "7") {
      showThreeMachineGuide();
      continue;
    }

    if (choice == "8") {
      configureABHostsInteractive(root, hosts, false);
      std::string dirA = readLine("Directory A URL", endpointFromHost(hosts.aHost, 8081));
      std::string dirB = readLine("Directory B URL", endpointFromHost(hosts.bHost, 8081));
      std::string issuer = readLine("Issuer URL", endpointFromHost(hosts.aHost, 8082));
      std::string entry = readLine("Entry control URL fallback", endpointFromHost(hosts.aHost, 8083));
      std::string exitUrl = readLine("Exit control URL fallback", endpointFromHost(hosts.aHost, 8084));
      std::string minSources = readLine("Minimum directory sources", "2");
      std::string minOperators = readLine("Minimum operators per directory", "2");
      std::string federationTimeout = readLine("Federation wait timeout sec", "90");
      std::string timeoutSec = readLine("Client validation timeout sec", "50");
      std::string country = readLine("Preferred exit country code (optional)", "");
      std::string region = readLine("Preferred exit region (optional)", "");

      if (dirA.empty() || dirB.empty() || issuer.empty() || entry.empty() || exitUrl.empty()) {
        std::cout << "directory A/B, issuer URL, entry URL and exit URL are required\n";
        continue;
      }

      std::ostringstream cmd;
      cmd << shellEscape(script) << " three-machine-validate"
          << " --directory-a " << shellEscape(dirA)
          << " --directory-b " << shellEscape(dirB)
          << " --issuer-url " << shellEscape(issuer)
          << " --entry-url " << shellEscape(entry)
          << " --exit-url " << shellEscape(exitUrl)
          << " --min-sources " << shellEscape(minSources)
          << " --min-operators " << shellEscape(minOperators)
          << " --federation-timeout-sec " << shellEscape(federationTimeout)
          << " --timeout-sec " << shellEscape(timeoutSec);
      if (!country.empty()) {
        cmd << " --exit-country " << shellEscape(country);
      }
      if (!region.empty()) {
        cmd << " --exit-region " << shellEscape(region);
      }
      runCommand(cmd.str());
      continue;
    }

    if (choice == "9") {
      runTestsInteractive(root, script, hosts);
      continue;
    }

    if (choice == "10") {
      configureABHostsInteractive(root, hosts, true);
      continue;
    }

    std::cout << "invalid selection\n";
  }
}
