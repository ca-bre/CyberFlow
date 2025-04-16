// CyberFlow Integration for Vulnerability Manager
// This integrates the Python vulnerability module with the CyberFlow GUI

// Register new node types when script loads
document.addEventListener('DOMContentLoaded', () => {
  // Wait for diagram to be initialized
  setTimeout(() => {
    const diagram = window.activeDiagram;
    if (diagram) {
      // Register custom node templates
      diagram.templates.scanner = { inputs: 0, output: true };
      diagram.templates.vulnerability = { inputs: 1, output: true };
      diagram.templates.attacker = { inputs: 1, output: true };
      
      // Override createNode method to handle custom node types
      const originalCreateNode = diagram.createNode;
      diagram.createNode = function(x, y, nodeType) {
        if (nodeType === "scanner") {
          const node = new ScannerNode(this, x, y);
          this.nodes.push(node);
          return node;
        } else if (nodeType === "vulnerability") {
          const node = new VulnerabilityNode(this, x, y);
          this.nodes.push(node);
          return node;
        } else if (nodeType === "attacker") {
          const node = new AttackNode(this, x, y);
          this.nodes.push(node);
          return node;
        } else {
          return originalCreateNode.call(this, x, y, nodeType);
        }
      };
      
      console.log("CyberFlow security nodes registered");
    }
  }, 500);
});

// Create a custom CyberFlow node type for vulnerability scanning
class ScannerNode extends FlowNode {
  constructor(diagram, x, y) {
    super(diagram, x, y, "scanner");
    
    // Override the default node appearance
    this.header.innerText = "Port Scanner";
    this.dom.style.width = "220px";
    
    // Replace standard body with scanner configuration
    this.body.innerHTML = "";
    
    // Target input
    const targetLabel = document.createElement("label");
    targetLabel.innerText = "Target IP:";
    const targetInput = document.createElement("input");
    targetInput.type = "text";
    targetInput.value = "127.0.0.1";
    targetInput.placeholder = "IP address";
    this.body.appendChild(targetLabel);
    this.body.appendChild(targetInput);
    
    // Port range input
    const portLabel = document.createElement("label");
    portLabel.innerText = "Port Range:";
    const portInput = document.createElement("input");
    portInput.type = "text";
    portInput.value = "1-1000";
    portInput.placeholder = "e.g., 1-1000,3389";
    this.body.appendChild(portLabel);
    this.body.appendChild(portInput);
    
    // Scan button
    const scanButton = document.createElement("button");
    scanButton.innerText = "Run Scan";
    scanButton.style.marginTop = "10px";
    scanButton.style.width = "100%";
    scanButton.style.padding = "5px";
    scanButton.addEventListener("click", () => this.runScan());
    this.body.appendChild(scanButton);
    
    // Status indicator
    this.statusDiv = document.createElement("div");
    this.statusDiv.innerText = "Ready";
    this.statusDiv.style.marginTop = "10px";
    this.statusDiv.style.padding = "5px";
    this.statusDiv.style.backgroundColor = "#f0f0f0";
    this.statusDiv.style.borderRadius = "3px";
    this.body.appendChild(this.statusDiv);
    
    // Progress bar
    this.progressContainer = document.createElement("div");
    this.progressContainer.style.marginTop = "10px";
    this.progressContainer.style.border = "1px solid #ccc";
    this.progressContainer.style.borderRadius = "3px";
    this.progressContainer.style.height = "20px";
    this.progressContainer.style.overflow = "hidden";
    this.progressContainer.style.display = "none";
    
    this.progressBar = document.createElement("div");
    this.progressBar.style.height = "100%";
    this.progressBar.style.width = "0%";
    this.progressBar.style.backgroundColor = "#4CAF50";
    this.progressBar.style.transition = "width 0.3s";
    
    this.progressContainer.appendChild(this.progressBar);
    this.body.appendChild(this.progressContainer);
    
    // Run button
    const runButton = document.createElement("button");
    runButton.innerText = "Assess Vulnerabilities";
    runButton.style.marginTop = "10px";
    runButton.style.width = "100%";
    runButton.style.padding = "5px";
    runButton.addEventListener("click", () => this.runVulnerabilityCheck());
    this.body.appendChild(runButton);
    
    // Results display (collapsible)
    const resultsHeader = document.createElement("div");
    resultsHeader.innerText = "Results (click to expand)";
    resultsHeader.style.marginTop = "10px";
    resultsHeader.style.fontWeight = "bold";
    resultsHeader.style.cursor = "pointer";
    this.body.appendChild(resultsHeader);
    
    this.resultsDiv = document.createElement("div");
    this.resultsDiv.style.marginTop = "5px";
    this.resultsDiv.style.display = "none";
    this.resultsDiv.style.maxHeight = "200px";
    this.resultsDiv.style.overflow = "auto";
    this.resultsDiv.style.border = "1px solid #ddd";
    this.resultsDiv.style.padding = "5px";
    this.body.appendChild(this.resultsDiv);
    
    // Toggle results visibility
    resultsHeader.addEventListener("click", () => {
      this.resultsDiv.style.display = this.resultsDiv.style.display === "none" ? "block" : "none";
    });
    
    // Report link
    this.reportLink = document.createElement("a");
    this.reportLink.innerText = "View Full Report";
    this.reportLink.style.display = "none";
    this.reportLink.style.marginTop = "10px";
    this.reportLink.setAttribute("target", "_blank");
    this.body.appendChild(this.reportLink);
    
    // References
    this.runButton = runButton;
    this.vulnResults = null;
    
    // Create output terminal
    let outTerm = this.createTerminal(false, 0);
    this.outputTerminals.push(outTerm);
  }
  
  async runVulnerabilityCheck() {
    // Get the input value (scan results)
    const scanResults = this.getInputValues()[0];
    
    if (!scanResults) {
      this.updateStatus("Error: No scan data available", true);
      return;
    }
    
    this.updateStatus("Starting vulnerability assessment...");
    this.runButton.disabled = true;
    this.resultsDiv.style.display = "none";
    this.progressContainer.style.display = "block";
    this.updateProgress(0);
    this.reportLink.style.display = "none";
    
    try {
      // Start the vulnerability assessment via API
      const response = await fetch('/api/assess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_results: scanResults })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to start vulnerability assessment');
      }
      
      // Poll for status and results
      let isCompleted = false;
      let errorOccurred = false;
      
      while (!isCompleted && !errorOccurred) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Poll every second
        
        const statusResponse = await fetch('/api/assess/status');
        if (!statusResponse.ok) {
          errorOccurred = true;
          continue;
        }
        
        const statusData = await statusResponse.json();
        
        // Update progress
        this.updateProgress(statusData.progress || 0);
        
        // Check for completion or error
        if (statusData.status === 'completed') {
          isCompleted = true;
          this.vulnResults = statusData.results;
          
          // Count vulnerable hosts
          const vulnerableCount = this.countVulnerableHosts(this.vulnResults);
          this.updateStatus(`Assessment complete. Found ${vulnerableCount} vulnerable hosts.`);
          
          // Display results summary
          this.displayResultsSummary(this.vulnResults);
          
          // Update the report link if available
          if (statusData.output_file) {
            const reportFile = statusData.output_file.split('/').pop();
            this.reportLink.href = `/api/reports/${reportFile}`;
            this.reportLink.style.display = "block";
          }
          
          // Get available HTML reports
          const reportsResponse = await fetch('/api/reports');
          if (reportsResponse.ok) {
            const reports = await reportsResponse.json();
            // Find the most recent HTML report
            const htmlReports = reports.filter(r => r.filename.endsWith('.html'));
            if (htmlReports.length > 0) {
              this.reportLink.href = htmlReports[0].path;
              this.reportLink.style.display = "block";
            }
          }
          
          // Update node value with vulnerability results
          this.setValue(JSON.stringify(this.vulnResults));
          
          // Notify the diagram to run logic (propagate values)
          if (this.diagram) {
            this.diagram.runLogic();
          }
        } 
        else if (statusData.status === 'error') {
          errorOccurred = true;
          throw new Error(statusData.error || 'An error occurred during vulnerability assessment');
        }
        else {
          // Update status message
          this.updateStatus(`Assessing vulnerabilities... ${Math.round(statusData.progress || 0)}%`);
        }
      }
    } catch (error) {
      this.updateStatus(`Error: ${error.message}`, true);
    } finally {
      this.runButton.disabled = false;
      this.resultsDiv.style.display = "block";
    }
  }
  
  updateStatus(message, isError = false) {
    this.statusDiv.innerText = message;
    this.statusDiv.style.backgroundColor = isError ? "#ffdddd" : "#f0f0f0";
    this.statusDiv.style.color = isError ? "#cc0000" : "#000000";
  }
  
  updateProgress(percent) {
    this.progressBar.style.width = `${percent}%`;
    // Hide progress bar when completed
    if (percent >= 100) {
      setTimeout(() => {
        this.progressContainer.style.display = "none";
      }, 1000);
    }
  }
  
  countVulnerableHosts(vulnResults) {
    let count = 0;
    for (const ip in vulnResults) {
      if (vulnResults[ip].vulnerabilities && 
          vulnResults[ip].vulnerabilities.some(v => v.is_vulnerable)) {
        count++;
      }
    }
    return count;
  }
  
  displayResultsSummary(vulnResults) {
    this.resultsDiv.innerHTML = "";
    
    for (const ip in vulnResults) {
      if (!vulnResults[ip].vulnerabilities) continue;
      
      const hostDiv = document.createElement("div");
      hostDiv.style.marginBottom = "10px";
      
      const hostHeader = document.createElement("div");
      hostHeader.innerText = `Host: ${ip}`;
      hostHeader.style.fontWeight = "bold";
      hostDiv.appendChild(hostHeader);
      
      // Count vulnerabilities
      const vulns = vulnResults[ip].vulnerabilities;
      const vulnCount = vulns.filter(v => v.is_vulnerable).length;
      
      const vulnSummary = document.createElement("div");
      vulnSummary.innerText = `Found ${vulnCount} vulnerabilities in ${vulns.length} checks`;
      vulnSummary.style.marginLeft = "10px";
      hostDiv.appendChild(vulnSummary);
      
      // List up to 3 vulnerability names
      if (vulnCount > 0) {
        const vulnList = document.createElement("ul");
        vulnList.style.margin = "5px 0 0 20px";
        vulnList.style.paddingLeft = "10px";
        
        vulns.filter(v => v.is_vulnerable)
             .slice(0, 3)
             .forEach(v => {
               const vulnItem = document.createElement("li");
               vulnItem.innerText = `${v.name} on port ${v.port} (${v.service})`;
               vulnItem.style.color = "#cc0000";
               vulnList.appendChild(vulnItem);
             });
        
        hostDiv.appendChild(vulnList);
      }
      
      this.resultsDiv.appendChild(hostDiv);
    }
  }
  
  getOutputValue() {
    return this.vulnResults;
  }
}

// Create an attack manager node
class AttackNode extends FlowNode {
  constructor(diagram, x, y) {
    super(diagram, x, y, "attacker");
    
    // Override the default node appearance
    this.header.innerText = "Attack Manager";
    this.dom.style.width = "240px";
    
    // Replace standard body
    this.body.innerHTML = "";
    
    // Create input terminal
    let inTerm = this.createTerminal(true, 0);
    this.inputTerminals.push(inTerm);
    
    // Status display
    this.statusDiv = document.createElement("div");
    this.statusDiv.innerText = "Waiting for vulnerability data...";
    this.statusDiv.style.padding = "5px";
    this.statusDiv.style.backgroundColor = "#f0f0f0";
    this.statusDiv.style.borderRadius = "3px";
    this.body.appendChild(this.statusDiv);
    
    // Progress bar
    this.progressContainer = document.createElement("div");
    this.progressContainer.style.marginTop = "10px";
    this.progressContainer.style.border = "1px solid #ccc";
    this.progressContainer.style.borderRadius = "3px";
    this.progressContainer.style.height = "20px";
    this.progressContainer.style.overflow = "hidden";
    this.progressContainer.style.display = "none";
    
    this.progressBar = document.createElement("div");
    this.progressBar.style.height = "100%";
    this.progressBar.style.width = "0%";
    this.progressBar.style.backgroundColor = "#4CAF50";
    this.progressBar.style.transition = "width 0.3s";
    
    this.progressContainer.appendChild(this.progressBar);
    this.body.appendChild(this.progressContainer);
    
    // Options area
    const optionsDiv = document.createElement("div");
    optionsDiv.style.marginTop = "10px";
    this.body.appendChild(optionsDiv);
    
    // Auto-attack option
    const autoAttackLabel = document.createElement("label");
    autoAttackLabel.innerHTML = "<input type='checkbox'> Auto-attack vulnerabilities";
    autoAttackLabel.style.display = "block";
    autoAttackLabel.style.marginBottom = "5px";
    optionsDiv.appendChild(autoAttackLabel);
    
    // Attack button
    const attackButton = document.createElement("button");
    attackButton.innerText = "Run Attacks";
    attackButton.style.width = "100%";
    attackButton.style.padding = "5px";
    attackButton.addEventListener("click", () => this.runAttacks());
    this.body.appendChild(attackButton);
    
    // Results display
    const resultsHeader = document.createElement("div");
    resultsHeader.innerText = "Attack Results";
    resultsHeader.style.marginTop = "10px";
    resultsHeader.style.fontWeight = "bold";
    resultsHeader.style.cursor = "pointer";
    this.body.appendChild(resultsHeader);
    
    this.resultsDiv = document.createElement("div");
    this.resultsDiv.style.marginTop = "5px";
    this.resultsDiv.style.maxHeight = "200px";
    this.resultsDiv.style.overflow = "auto";
    this.resultsDiv.style.border = "1px solid #ddd";
    this.resultsDiv.style.padding = "5px";
    this.resultsDiv.style.display = "none";
    this.body.appendChild(this.resultsDiv);
    
    // Toggle results visibility
    resultsHeader.addEventListener("click", () => {
      this.resultsDiv.style.display = this.resultsDiv.style.display === "none" ? "block" : "none";
    });
    
    // Report link
    this.reportLink = document.createElement("a");
    this.reportLink.innerText = "View Attack Report";
    this.reportLink.style.display = "none";
    this.reportLink.style.marginTop = "10px";
    this.reportLink.setAttribute("target", "_blank");
    this.body.appendChild(this.reportLink);
    
    // References
    this.attackButton = attackButton;
    this.autoAttackCheckbox = autoAttackLabel.querySelector("input");
    this.attackResults = null;
    
    // Create output terminal for the final report
    let outTerm = this.createTerminal(false, 0);
    this.outputTerminals.push(outTerm);
  }
  
  async runAttacks() {
    // Get the input value (vulnerability assessment results)
    const vulnResults = this.getInputValues()[0];
    
    if (!vulnResults) {
      this.updateStatus("Error: No vulnerability data available", true);
      return;
    }
    
    this.updateStatus("Starting attacks...");
    this.attackButton.disabled = true;
    this.progressContainer.style.display = "block";
    this.updateProgress(0);
    this.reportLink.style.display = "none";
    this.resultsDiv.style.display = "none";
    
    try {
      // Start the attack process via API
      const response = await fetch('/api/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability_results: vulnResults })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to start attack process');
      }
      
      // Poll for status and results
      let isCompleted = false;
      let errorOccurred = false;
      
      while (!isCompleted && !errorOccurred) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Poll every second
        
        const statusResponse = await fetch('/api/attack/status');
        if (!statusResponse.ok) {
          errorOccurred = true;
          continue;
        }
        
        const statusData = await statusResponse.json();
        
        // Update progress
        this.updateProgress(statusData.progress || 0);
        
        // Check for completion or error
        if (statusData.status === 'completed') {
          isCompleted = true;
          this.attackResults = statusData.results;
          
          // Count successful attacks
          const successCount = this.countSuccessfulAttacks(this.attackResults);
          this.updateStatus(`Attacks complete. ${successCount} successful attacks.`);
          
          // Display results summary
          this.displayAttackSummary(this.attackResults);
          
          // Update the report link if available
          if (statusData.html_report) {
            const reportFile = statusData.html_report.split('/').pop();
            this.reportLink.href = `/api/reports/${reportFile}`;
            this.reportLink.style.display = "block";
          } else {
            // Get available HTML reports
            const reportsResponse = await fetch('/api/reports');
            if (reportsResponse.ok) {
              const reports = await reportsResponse.json();
              // Find the most recent HTML report
              const htmlReports = reports.filter(r => r.filename.includes('attack') && r.filename.endsWith('.html'));
              if (htmlReports.length > 0) {
                this.reportLink.href = htmlReports[0].path;
                this.reportLink.style.display = "block";
              }
            }
          }
          
          // Update node value with attack results
          this.setValue(JSON.stringify(this.attackResults));
          
          // Notify the diagram to run logic (propagate values)
          if (this.diagram) {
            this.diagram.runLogic();
          }
        } 
        else if (statusData.status === 'error') {
          errorOccurred = true;
          throw new Error(statusData.error || 'An error occurred during attack execution');
        }
        else {
          // Update status message
          this.updateStatus(`Running attacks... ${Math.round(statusData.progress || 0)}%`);
        }
      }
    } catch (error) {
      this.updateStatus(`Error: ${error.message}`, true);
    } finally {
      this.attackButton.disabled = false;
      this.resultsDiv.style.display = "block";
    }
  }
  
  updateStatus(message, isError = false) {
    this.statusDiv.innerText = message;
    this.statusDiv.style.backgroundColor = isError ? "#ffdddd" : "#f0f0f0";
    this.statusDiv.style.color = isError ? "#cc0000" : "#000000";
  }
  
  updateProgress(percent) {
    this.progressBar.style.width = `${percent}%`;
    // Hide progress bar when completed
    if (percent >= 100) {
      setTimeout(() => {
        this.progressContainer.style.display = "none";
      }, 1000);
    }
  }
  
  countSuccessfulAttacks(attackResults) {
    if (!attackResults || !attackResults.attacks) return 0;
    return attackResults.attacks.filter(a => a.success).length;
  }
  
  displayAttackSummary(attackResults) {
    this.resultsDiv.innerHTML = "";
    
    if (!attackResults || !attackResults.attacks || attackResults.attacks.length === 0) {
      this.resultsDiv.innerText = "No attack results available.";
      return;
    }
    
    // Group attacks by host
    const attacksByHost = {};
    for (const attack of attackResults.attacks) {
      if (!attacksByHost[attack.ip]) {
        attacksByHost[attack.ip] = [];
      }
      attacksByHost[attack.ip].push(attack);
    }
    
    // Display attacks by host
    for (const ip in attacksByHost) {
      const hostDiv = document.createElement("div");
      hostDiv.style.marginBottom = "10px";
      
      const hostHeader = document.createElement("div");
      hostHeader.innerText = `Host: ${ip}`;
      hostHeader.style.fontWeight = "bold";
      hostDiv.appendChild(hostHeader);
      
      // Count successful attacks
      const attacks = attacksByHost[ip];
      const successCount = attacks.filter(a => a.success).length;
      
      const attackSummary = document.createElement("div");
      attackSummary.innerText = `${successCount} successful attacks out of ${attacks.length} attempted`;
      attackSummary.style.marginLeft = "10px";
      hostDiv.appendChild(attackSummary);
      
      // List attacks
      const attackList = document.createElement("ul");
      attackList.style.margin = "5px 0 0 20px";
      attackList.style.paddingLeft = "10px";
      
      attacks.forEach(attack => {
        const attackItem = document.createElement("li");
        attackItem.innerText = `${attack.vulnerability} on port ${attack.port} (${attack.service}) - ${attack.success ? 'SUCCESS' : 'FAILED'}`;
        attackItem.style.color = attack.success ? "#008800" : "#cc0000";
        attackList.appendChild(attackItem);
      });
      
      hostDiv.appendChild(attackList);
      this.resultsDiv.appendChild(hostDiv);
    }
  }
  
  getOutputValue() {
    return this.attackResults;
  }
  
  async runScan() {
    const target = this.targetInput.value.trim();
    const portRange = this.portInput.value.trim();
    
    if (!target) {
      this.updateStatus("Error: Target IP required", true);
      return;
    }
    
    this.updateStatus("Starting scan...");
    this.scanButton.disabled = true;
    this.progressContainer.style.display = "block";
    this.updateProgress(0);
    
    try {
      // Start the scan via API
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, ports: portRange })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to start scan');
      }
      
      // Poll for status and results
      let isCompleted = false;
      let errorOccurred = false;
      
      while (!isCompleted && !errorOccurred) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Poll every second
        
        const statusResponse = await fetch('/api/scan/status');
        if (!statusResponse.ok) {
          errorOccurred = true;
          continue;
        }
        
        const statusData = await statusResponse.json();
        
        // Update progress
        this.updateProgress(statusData.progress || 0);
        
        // Check for completion or error
        if (statusData.status === 'completed') {
          isCompleted = true;
          this.scanResults = statusData.results;
          
          // Count open ports
          let totalOpenPorts = 0;
          for (const ip in this.scanResults) {
            totalOpenPorts += this.scanResults[ip].length;
          }
          
          this.updateStatus(`Scan complete. Found ${totalOpenPorts} open ports.`);
          
          // Update node value with scan results
          this.setValue(JSON.stringify(this.scanResults));
          
          // Notify the diagram to run logic (propagate values)
          if (this.diagram) {
            this.diagram.runLogic();
          }
        } 
        else if (statusData.status === 'error') {
          errorOccurred = true;
          throw new Error(statusData.error || 'An error occurred during scanning');
        }
        else {
          // Update status message
          this.updateStatus(`Scanning... ${Math.round(statusData.progress || 0)}%`);
        }
      }
    } catch (error) {
      this.updateStatus(`Error: ${error.message}`, true);
    } finally {
      this.scanButton.disabled = false;
    }
  }
  
  updateStatus(message, isError = false) {
    this.statusDiv.innerText = message;
    this.statusDiv.style.backgroundColor = isError ? "#ffdddd" : "#f0f0f0";
    this.statusDiv.style.color = isError ? "#cc0000" : "#000000";
  }
  
  updateProgress(percent) {
    this.progressBar.style.width = `${percent}%`;
    // Hide progress bar when completed
    if (percent >= 100) {
      setTimeout(() => {
        this.progressContainer.style.display = "none";
      }, 1000);
    }
  }
  
  getOutputValue() {
    return this.scanResults;
  }
}

// Create a vulnerability assessment node
class VulnerabilityNode extends FlowNode {
  constructor(diagram, x, y) {
    super(diagram, x, y, "vulnerability");
    
    // Override the default node appearance
    this.header.innerText = "Vulnerability Assessment";
    this.dom.style.width = "240px";
    
    // Replace standard body
    this.body.innerHTML = "";
    
    // Create input terminal
    let inTerm = this.createTerminal(true, 0);
    this.inputTerminals.push(inTerm);
    
    // Status display
    this.statusDiv = document.createElement("div");
    this.statusDiv.innerText = "Waiting for scan data...";
    this.statusDiv.style.padding = "5px";
    this.statusDiv.style.backgroundColor = "#f0f0f0";
    this.statusDiv.style.borderRadius = "3px";
    this.body.appendChild(this.statusDiv);
    
    // Progress bar container
    this.progressContainer = document.createElement("div");
    Object.assign(this.progressContainer.style, {
      marginTop: "10px",
      border: "1px solid #ccc",
      borderRadius: "3px",
      height: "20px",
      overflow: "hidden",
      display: "none"
    });

    // Progress bar itself
    this.progressBar = document.createElement("div");
    Object.assign(this.progressBar.style, {
      width: "0%",
      height: "100%",
      backgroundColor: "#4CAF50",
      transition: "width 0.3s ease-in-out"
    });

    // Append progress bar to container and add it to the node
    this.progressContainer.appendChild(this.progressBar);
    this.body.appendChild(this.progressContainer);
  }

  // Example method to show the progress bar and update its progress
  updateProgress(percent) {
    this.progressContainer.style.display = "block";
    this.progressBar.style.width = `${Math.min(Math.max(percent, 0), 100)}%`;
  }
}

