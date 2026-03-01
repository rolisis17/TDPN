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

void runTestsInteractive(const std::string &root, const std::string &script) {
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
      std::string host = readLine("Machine A public host/IP (optional)", "");
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
      std::string peerA = readLine("Machine A directory URL (e.g. http://A:8081)");
      std::string host = readLine("Machine B public host/IP (optional)", "");
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
      std::string dirA = readLine("Directory A URL (e.g. http://A:8081)");
      std::string dirB = readLine("Directory B URL (e.g. http://B:8081)");
      std::string issuer = readLine("Issuer URL (e.g. http://A:8082)");
      std::string entry = readLine("Entry control URL fallback (e.g. http://A:8083)");
      std::string exitUrl = readLine("Exit control URL fallback (e.g. http://A:8084)");
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
      std::string host = readLine("Public host/IP for this server machine (required)");
      if (host.empty()) {
        std::cout << "host is required\n";
        continue;
      }
      std::string operatorId = readLine("Operator ID", "");
      std::string adminToken = readLine("Issuer admin token (blank=auto)", "");
      std::string peers = readLine("Peer directory URLs CSV (optional, for federation)", "");

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
      std::string dirs = readLine("Directory URLs CSV (e.g. http://A:8081,http://B:8081)");
      std::string issuer = readLine("Issuer URL (e.g. http://A:8082)");
      std::string entry = readLine("Entry control URL fallback (e.g. http://A:8083)");
      std::string exitUrl = readLine("Exit control URL fallback (e.g. http://A:8084)");
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
      std::string dirA = readLine("Directory A URL (e.g. http://A:8081)");
      std::string dirB = readLine("Directory B URL (e.g. http://B:8081)");
      std::string issuer = readLine("Issuer URL (e.g. http://A:8082)");
      std::string entry = readLine("Entry control URL fallback (e.g. http://A:8083)");
      std::string exitUrl = readLine("Exit control URL fallback (e.g. http://A:8084)");
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
      runTestsInteractive(root, script);
      continue;
    }

    std::cout << "invalid selection\n";
  }
}
