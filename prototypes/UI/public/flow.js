class Diagram {
  constructor(rootElement) {
    // Main container
    this.root = rootElement;
    this.root.classList.add("flow_diagram");

    // Pan container for nodes
    this.panDiv = document.createElement("div");
    this.panDiv.classList.add("flow_pan");
    this.root.appendChild(this.panDiv);

    // for node connections
    this.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    this.svg.classList.add("flow_svg");
    this.root.appendChild(this.svg);

    this.nodes = [];
    this.connections = [];

    // Example of a template node:
    this.templates = {
      Addition: {
        inputs: 2,
        output: true,
        compute(values) {
          let sum = 0;
          for (const v of values) {
            sum += parseFloat(v) || 0;
          }
          console.log(sum);
          return sum;
        }
      },
      SamplePy: {
        inputs: 1,
        output: true,
        async compute (values) {
          let resp = await callPython({script: "sample.py", some: `${values[0]}`}).then(pyResp => 
          {
            return pyResp;
          });
          return resp;
        }
      },
      PortScanner: {
        inputs: 2,
        output: true,
        async compute (values) {
          let resp = await callPython({script: "cidr_scanner.py", ip:`${values[0]}`, ports: `${values[1]}`}).then(pyResp =>
          {
            return pyResp;
          });
          return resp;
        }
      },
      SmileyBackdoor: {
        inputs: 1,
        output: true,
        async compute (values) {
          let resp = await callPython({script: "smiley_backdoor_flow.py", target: `${values[0]}`}).then(pyResp => {
            return pyResp;
          });
          return resp;
        }
      },
      VulnerabilitiesScanner: {
        inputs: 1,
        output: true,
        async compute (values) {
          // Expects the output from PortScanner as input
          let scanResults = values[0];
          
          // If input is a string (which it likely will be from PortScanner node), 
          // try to parse it as JSON
          if (typeof scanResults === 'string') {
            try {
              scanResults = JSON.parse(scanResults);
            } catch(e) {
              return { 
                status: "error",
                message: "Failed to parse port scanner results",
                error: e.message
              };
            }
          }
          
          // Pass the scan results to the vulnerability scanner
          let resp = await callPython({
            script: "vulnerability_flow.py", 
            scan_results: scanResults
          }).then(pyResp => {
            return pyResp;
          });
          
          return resp;
        }
      },
      VsftpdScanner: {
        inputs: 1,
        output: true,
        async compute(values) {
          let scanResults = values[0];
          if (typeof scanResults === 'string') {
            try {
              scanResults = JSON.parse(scanResults);
            } catch (e) {
              return {
                status: "error",
                message: "Failed to parse port scanner results",
                error: e.message
              };
            }
          }
          let resp = await callPython({
            script: "vsftpd_scanner.py",
            scan_results: scanResults
          }).then(pyResp => {
            return pyResp;
          });
          return resp;
        }
      },
      ShellshockScanner: {
        inputs: 1,
        output: true,
        async compute(values) {
          // Expects the output from PortScanner as input
          let scanResults = values[0];
          
          // If input is a string (which it likely will be from PortScanner node), 
          // try to parse it as JSON
          if (typeof scanResults === 'string') {
            try {
              scanResults = JSON.parse(scanResults);
            } catch(e) {
              return { 
                status: "error",
                message: "Failed to parse port scanner results",
                error: e.message
              };
            }
          }
          
          // Pass the scan results to the shellshock scanner
          let resp = await callPython({
            script: "shellshock_scanner.py", 
            scan_results: scanResults
          }).then(pyResp => {
            return pyResp;
          });
          
          return resp;
        }
      },
      ShellshockExploit: {
        inputs: 3,
        output: true,
        async compute(values) {
          let target = values[0];
          let cgiPath = values[1] || "/cgi-bin/vulnerable.cgi";
          let command = values[2] || "echo 'Shellshock Test'";
          
          let resp = await callPython({
            script: "shellshock_exploit.py",
            target: target,
            cgi_path: cgiPath,
            command: command
          }).then(pyResp => {
            return pyResp;
          });
          
          return resp;
        }
    }
  }
    
    async function callPython(dataToSend) {
      const response = await fetch('/run-python', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(dataToSend)
      });
      const result = await response.json();
      console.log('Python result:', result);
      return result;
    }

    this.darkMode = false;
  }

  setDarkMode(enabled) {
    this.darkMode = enabled;
    if (enabled) {
      this.root.style.backgroundColor = "#333";
      this.root.style.color = "#000";
    } else {
      this.root.style.backgroundColor = "#ecf1f1";
      this.root.style.color = "#000";
    }
  }

  createNode(x, y, nodeType) {
    const node = new FlowNode(this, x, y, nodeType);
    this.nodes.push(node);
    return node;
  }

  removeNode(node) {
    // remove from DOM
    node.remove();
    // remove from array
    this.nodes = this.nodes.filter(n => n !== node);
    // remove any references to it
    const deadConns = this.connections.filter(c => c.fromNode === node || c.toNode === node);
    deadConns.forEach(c => c.remove());
    this.connections = this.connections.filter(c => !deadConns.includes(c));
  }

  isAsyncFunction(fn) {
    return fn && fn.constructor && fn.constructor.name === 'AsyncFunction';
  }

  async runLogic() {
    // 1) parse standard node values
    for (let n of this.nodes) {
      if (n.nodeType === "standard") {
        n.parseValueByDataType();
      }
    }
    // 2) evaluate templates (like Addition), will likely move out into parser later
    for (let n of this.nodes) {
      if (n.nodeType !== "standard") {
        const template = this.templates[n.nodeType];
          if (!template) continue;
          const inputs = n.getInputValues();

        if (this.isAsyncFunction(template.compute)) {
          let result =  await template.compute(inputs);
          n.setValue(result.message);
        } else {
          let result = template.compute(inputs);
          n.setValue(result);
        }
      }
    }
  }

  exportJSON() {
    return {
      darkMode: this.darkMode,
      nodes: this.nodes.map(n => ({
        id: n.id,
        nodeType: n.nodeType,
        x: n.x,
        y: n.y,
        dataType: n.dataType,
        value: n.value
      })),
      connections: this.connections.map(c => ({
        fromNode: c.fromNode.id,
        toNode: c.toNode.id,
        toIndex: c.toIndex
      }))
    };
  }

  importJSON(data) {
    // clear existing
    this.nodes.forEach(n => n.remove());
    this.connections.forEach(c => c.remove());
    this.nodes = [];
    this.connections = [];

    if (data.darkMode != null) {
      this.setDarkMode(data.darkMode);
    }

    // create nodes
    if (data.nodes) {
      data.nodes.forEach(nd => {
        const node = new FlowNode(this, nd.x, nd.y, nd.nodeType);
        node.id = nd.id;
        node.dataType = nd.dataType;
        node.value = nd.value;
        node.refreshUI();
        this.nodes.push(node);
      });
    }
    // connections
    if (data.connections) {
      data.connections.forEach(cd => {
        const fromN = this.nodes.find(n => n.id === cd.fromNode);
        const toN   = this.nodes.find(n => n.id === cd.toNode);
        if (fromN && toN) {
          let conn = new Connection(this, fromN, toN, cd.toIndex);
          this.connections.push(conn);
        }
      });
    }
  }
}

// Increments per created node
let NODE_COUNTER = 1;

class FlowNode {
  constructor(diagram, x, y, nodeType) {
    this.diagram = diagram;
    this.x = x - diagram.root.getBoundingClientRect().left;
    this.y = y - diagram.root.getBoundingClientRect().top;
    this.nodeType = nodeType;
    this.id = NODE_COUNTER++;

    this.dataType = "string";
    this.value = "";

    // DOM
    this.dom = document.createElement("div");
    this.dom.classList.add("flow_node");
    this.dom.style.left = this.x + "px";
    this.dom.style.top = this.y + "px";

    // header
    this.header = document.createElement("div");
    this.header.classList.add("flow_node_header");
    this.header.innerText = nodeType;
    this.dom.appendChild(this.header);

    // body
    this.body = document.createElement("div");
    this.body.classList.add("flow_node_body");
    this.dom.appendChild(this.body);

    this.inputTerminals = [];
    this.outputTerminals = [];

    // Build UI
    if (nodeType === "standard") {
      // single output
      this.buildStandardBody();
      let out = this.createTerminal(false, 0);
      this.outputTerminals.push(out);
    } else {
      // template node => e.g. Addition
      let tmpl = this.diagram.templates[nodeType];
      if (tmpl) {
        this.resultLabel = document.createElement("div");
        this.resultLabel.innerText = "Result: ";
        this.body.appendChild(this.resultLabel);

        // Create input terminals
        for (let i = 0; i < tmpl.inputs; i++) {
          let term = this.createTerminal(true, i);
          this.inputTerminals.push(term);
        }
        // Output terminal (if any)
        if (tmpl.output) {
          let outTerm = this.createTerminal(false, 0);
          this.outputTerminals.push(outTerm);
        }
      }
    }

    this.makeDraggable();

    // Right click on node => Delete Node
    this.dom.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.showNodeContextMenu(e);
    });

    this.diagram.panDiv.appendChild(this.dom);
    this.dom.__nodeId = this.id;
  }

  showNodeContextMenu(e) {
    const menu = document.createElement("ul");
    menu.classList.add("context-menu");
    menu.style.display = "none";
    document.body.appendChild(menu);

    const deleteItem = document.createElement("li");
    deleteItem.innerText = "Delete Node";
    deleteItem.onclick = (evt) => {
      evt.stopPropagation();
      this.diagram.removeNode(this);
      menu.remove();
    };
    menu.appendChild(deleteItem);

    // position
    menu.style.left = e.clientX + "px";
    menu.style.top = e.clientY + "px";
    menu.style.display = "block";

    const hide = () => {
      menu.remove();
      document.removeEventListener("click", hide);
    };
    document.addEventListener("click", hide);
  }

  buildStandardBody() {
    // Data type
    const typeLabel = document.createElement("label");
    typeLabel.innerText = "Type:";
    const typeSelect = document.createElement("select");
    ["string", "bool", "int", "double", "object"].forEach(dt => {
      let opt = document.createElement("option");
      opt.value = dt;
      opt.innerText = dt;
      typeSelect.appendChild(opt);
    });
    typeSelect.value = this.dataType;
    typeSelect.onchange = () => {
      this.dataType = typeSelect.value;
    };
    this.body.appendChild(typeLabel);
    this.body.appendChild(typeSelect);
  
    const valLabel = document.createElement("label");
    valLabel.innerText = "Value:";
    const valInput = document.createElement("input");
    valInput.type = "text";
    valInput.value = this.value;
    valInput.onchange = () => {
      this.value = valInput.value;
    };
    this.body.appendChild(valLabel);
    this.body.appendChild(valInput);
  
    let inTerm = this.createTerminal(true, 0);
    this.inputTerminals.push(inTerm);
  }  

  createTerminal(isInput, index) {
    const term = document.createElement("div");
    term.classList.add("node-terminal");
    if (isInput) {
      term.classList.add("node-input");
      term.style.top = (40 + index*20) + "px";
      term.dataset.type = "input";
      term.dataset.index = index;
    } else {
      term.classList.add("node-output");
      term.style.top = (40 + index*20) + "px";
      term.dataset.type = "output";
      term.dataset.index = index;
    }

    term.addEventListener("mousedown", (e) => {
      e.stopPropagation();
      e.preventDefault();
      this.onTerminalMouseDown(term, e);
    });

    this.body.appendChild(term);
    return term;
  }

  onTerminalMouseDown(term, e) {
    const path = document.createElementNS("http://www.w3.org/2000/svg","path");
    path.setAttribute("stroke", "#333");
    path.setAttribute("fill", "none");
    path.setAttribute("stroke-width", "2");
    this.diagram.svg.appendChild(path);

    const rect = term.getBoundingClientRect();
    const diagRect = this.diagram.root.getBoundingClientRect();
    const sx = rect.left + rect.width/2 - diagRect.left;
    const sy = rect.top + rect.height/2 - diagRect.top;

    const updatePath = (mx, my, tx, ty) => {
      let dx = (tx - mx) / 2;
      path.setAttribute("d", `M ${mx} ${my} C ${mx+dx} ${my}, ${tx-dx} ${ty}, ${tx} ${ty}`);
    };

    const onMouseMove = (ev) => {
      let mx = ev.clientX - diagRect.left;
      let my = ev.clientY - diagRect.top;
      updatePath(sx, sy, mx, my);
    };

    const onMouseUp = (ev) => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      path.remove();

      // see if we dropped on a node terminal
      const upTarget = document.elementFromPoint(ev.clientX, ev.clientY);
      if (!upTarget || !upTarget.classList.contains("node-terminal")) return;

      const fromIsOutput = term.dataset.type === "output";
      const toIsInput = upTarget.dataset.type === "input";
      if (!fromIsOutput || !toIsInput) return; // must be output->input

      const otherNodeId = upTarget.closest(".flow_node").__nodeId;
      let otherNode = this.diagram.nodes.find(n => n.id == otherNodeId);
      if (!otherNode) return;

      let toIndex = parseInt(upTarget.dataset.index, 10);
      let conn = new Connection(this.diagram, this, otherNode, toIndex);
      this.diagram.connections.push(conn);
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  }

  makeDraggable() {
    let offsetX = 0;
    let offsetY = 0;

    const onMouseDown = (e) => {
      if (e.target !== this.header) return;
      offsetX = e.clientX - this.dom.offsetLeft;
      offsetY = e.clientY - this.dom.offsetTop;
      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    };

    const onMouseMove = (ev) => {
      this.x = ev.clientX - offsetX;
      this.y = ev.clientY - offsetY;
      this.dom.style.left = this.x + "px";
      this.dom.style.top = this.y + "px";
      // update relevant connection paths
      this.diagram.connections.forEach(c => {
        if (c.fromNode === this || c.toNode === this) {
          c.redraw();
        }
      });
    };

    const onMouseUp = () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };

    this.header.addEventListener("mousedown", onMouseDown);
  }

  remove() {
    if (this.dom.parentNode) {
      this.dom.parentNode.removeChild(this.dom);
    }
  }

  refreshUI() {
    if (this.nodeType === "standard") {
      // sync data type & main value
      let sel = this.body.querySelector("select");
      if (sel) sel.value = this.dataType;
      let valInput = this.body.querySelectorAll("input")[0]; // first input
      if (valInput) valInput.value = this.value;
      // override is left blank on restore
    } else {
      if (this.resultLabel) {
        this.resultLabel.innerText = "Result: " + (this.value || "");
      }
    }
  }

  parseValueByDataType() {
    if (this.nodeType !== "standard") return;
  
    // If there's at least one input connection, adopt the upstream node's output:
    const inputConns = this.diagram.connections.filter(c => c.toNode === this);
    if (inputConns.length > 0) {
      const upstreamVal = inputConns[0].fromNode.getOutputValue();
      this.value = upstreamVal; // store in .value
  
      // Force the node's text field to display the new value
      let valInput = this.body.querySelector("input[type='text']");
      if (valInput) {
        valInput.value = upstreamVal;
      }
    }
  
    // Now parse the final string in this.value according to dataType
    let raw = this.value;
    switch (this.dataType) {
      case "int":
        this._parsedValue = parseInt(raw, 10) || 0;
        break;
      case "double":
        this._parsedValue = parseFloat(raw) || 0.0;
        break;
      case "bool":
        this._parsedValue = (String(raw).toLowerCase() === "true");
        break;
      case "object":
        try {
          this._parsedValue = JSON.parse(raw);
        } catch {
          console.warn("Invalid JSON in node", this.id);
          this._parsedValue = null;
        }
        break;
      case "string":
      default:
        this._parsedValue = raw;
        break;
    }
  }

  getOutputValue() {
    if (this.nodeType === "standard") {
      return this._parsedValue; 
    }
    return this.value; 
  }

  getInputValues() {
    // gather from connections
    let conns = this.diagram.connections.filter(c => c.toNode === this);
    // sort by index
    conns.sort((a,b) => a.toIndex - b.toIndex);
    return conns.map(c => c.fromNode.getOutputValue());
  }

  setValue(val) {
    this.value = val;
    if (this.nodeType === "standard") {
      // update main input box
      const valInput = this.body.querySelectorAll("input")[0];
      if (valInput) {
        valInput.value = val;
      }
    } else {
      if (this.resultLabel) {
        // Format objects and arrays for better display
        let displayValue = val;
        
        if (typeof val === 'object' && val !== null) {
          try {
            // For SmileyBackdoor, create a custom formatted display
            if (this.nodeType === "SmileyBackdoor" && val.status === "success") {
              // Create a pre element for formatting if it doesn't exist
              if (!this.resultPre) {
                this.resultPre = document.createElement("div");
                this.resultPre.style.maxHeight = "350px";
                this.resultPre.style.overflow = "auto";
                this.resultPre.style.backgroundColor = "#f8f9fa";
                this.resultPre.style.padding = "10px";
                this.resultPre.style.border = "1px solid #ddd";
                this.resultPre.style.borderRadius = "4px";
                this.resultPre.style.marginTop = "5px";
                this.resultPre.style.fontSize = "13px";
                this.resultPre.style.fontFamily = "Arial, sans-serif";
                this.body.appendChild(this.resultPre);
              }
              
              // Format backdoor results in a more user-friendly way
              let html = '';
              
              // Add operation status with appropriate color
              const statusColor = val.status === "success" ? "#28a745" : 
                                val.status === "partially_successful" ? "#ffc107" : "#dc3545";
              
              html += `<div style="margin-bottom:10px;">
                        <div style="font-weight:bold;font-size:14px;margin-bottom:5px;">Backdoor Operation</div>
                        <div>Target: <span style="font-weight:bold;">${val.target}</span></div>
                        <div>Status: <span style="color:${statusColor};font-weight:bold;">${val.status}</span></div>
                        <div>Timestamp: ${val.timestamp}</div>
                      </div>`;
              
              // Add server information section
              if (val.steps && val.steps.length > 0) {
                const checkResult = val.steps.find(step => step.step === "check_target")?.result;
                if (checkResult) {
                  html += `<div style="margin-bottom:10px;padding-top:5px;border-top:1px solid #ddd;">
                            <div style="font-weight:bold;margin-bottom:5px;">Target Information</div>
                            <div>Server: <span style="font-family:monospace;">${checkResult.server}</span></div>
                            <div>Detected: ${checkResult.technologies ? checkResult.technologies.join(", ") : "None"}</div>
                          </div>`;
                }
                
                // Add backdoor details
                const uploadResult = val.steps.find(step => step.step === "upload_backdoor")?.result;
                if (uploadResult && uploadResult.status === "success") {
                  html += `<div style="margin-bottom:10px;padding-top:5px;border-top:1px solid #ddd;">
                            <div style="font-weight:bold;margin-bottom:5px;">Backdoor Details</div>
                            <div>Filename: <span style="font-family:monospace;">${uploadResult.backdoor_name}</span></div>
                            <div>URL: <span style="font-family:monospace;word-break:break-all;">${val.backdoor_url}</span></div>
                          </div>`;
                }
                
                // Add command execution results
                const commandResults = val.steps.find(step => step.step === "test_commands")?.results;
                if (commandResults && commandResults.length > 0) {
                  html += `<div style="padding-top:5px;border-top:1px solid #ddd;">
                            <div style="font-weight:bold;margin-bottom:5px;">Command Execution Results</div>`;
                  
                  commandResults.forEach(cmd => {
                    const cmdStatus = cmd.status === "success" ? 
                      `<span style="color:#28a745;">✓</span>` : 
                      `<span style="color:#dc3545;">✗</span>`;
                      
                    html += `<div style="margin-bottom:8px;">
                              <div>${cmdStatus} <span style="font-family:monospace;font-weight:bold;">${cmd.command}</span></div>
                              <div style="background:#272822;color:#f8f8f2;padding:5px;border-radius:3px;margin-top:3px;font-family:monospace;white-space:pre-wrap;">${cmd.output}</div>
                            </div>`;
                  });
                  
                  html += `</div>`;
                }
              }
              
              // Add summary message
              if (val.message) {
                html += `<div style="margin-top:10px;padding:5px;background:${statusColor};color:white;border-radius:3px;font-weight:bold;">
                          ${val.message}
                        </div>`;
              }
              
              // Update the pre element with the formatted HTML
              this.resultPre.innerHTML = html;
              this.resultLabel.innerText = "Result: ";
              return;
            }
            // Format the VulnerabilityScanner output nicely
            else if (this.nodeType === "VulnerabilityScanner" && val.status === "success") {
              // Create a pre element for formatting if it doesn't exist
              if (!this.resultPre) {
                this.resultPre = document.createElement("div");
                this.resultPre.style.maxHeight = "350px";
                this.resultPre.style.overflow = "auto";
                this.resultPre.style.backgroundColor = "#f8f9fa";
                this.resultPre.style.padding = "10px";
                this.resultPre.style.border = "1px solid #ddd";
                this.resultPre.style.borderRadius = "4px";
                this.resultPre.style.marginTop = "5px";
                this.resultPre.style.fontSize = "13px";
                this.resultPre.style.fontFamily = "Arial, sans-serif";
                this.body.appendChild(this.resultPre);
              }
              
              // Format vulnerability results in a more user-friendly way
              let html = '';
              
              // Add scan summary
              const summary = val.summary;
              
              html += `<div style="margin-bottom:15px;">
                        <div style="font-weight:bold;font-size:15px;margin-bottom:5px;color:#2c3e50;">Vulnerability Scan Summary</div>
                        <div style="background:#e9f7ef;padding:10px;border-radius:4px;border-left:4px solid #27ae60;">
                          <div>Hosts scanned: <span style="font-weight:bold;">${summary.total_hosts}</span></div>
                          <div>Vulnerable hosts: <span style="font-weight:bold;">${summary.vulnerable_hosts}</span></div>
                          <div>Total vulnerabilities: <span style="font-weight:bold;">${summary.total_vulnerabilities}</span></div>
                          <div style="margin-top:5px;">Severity breakdown:</div>
                          <div style="display:flex;margin-top:3px;">
                            <div style="flex:1;text-align:center;background:#e74c3c;color:white;padding:3px;margin-right:2px;border-radius:3px;">Critical: ${summary.severity_breakdown.Critical}</div>
                            <div style="flex:1;text-align:center;background:#e67e22;color:white;padding:3px;margin-right:2px;border-radius:3px;">High: ${summary.severity_breakdown.High}</div>
                            <div style="flex:1;text-align:center;background:#f1c40f;color:white;padding:3px;margin-right:2px;border-radius:3px;">Medium: ${summary.severity_breakdown.Medium}</div>
                            <div style="flex:1;text-align:center;background:#3498db;color:white;padding:3px;border-radius:3px;">Low: ${summary.severity_breakdown.Low}</div>
                          </div>
                        </div>
                      </div>`;
              
              // Add host-specific information
              if (val.details) {
                html += `<div style="font-weight:bold;font-size:14px;margin-bottom:5px;color:#2c3e50;">Host Details</div>`;
                
                for (const [ip, hostData] of Object.entries(val.details)) {
                  if (!hostData.vulnerabilities || hostData.vulnerabilities.length === 0) {
                    continue;  // Skip hosts with no vulnerabilities
                  }
                  
                  // Risk level color
                  const riskLevelColors = {
                    "Critical": "#e74c3c",
                    "High": "#e67e22",
                    "Medium": "#f1c40f",
                    "Low": "#3498db"
                  };
                  
                  const riskColor = riskLevelColors[hostData.risk_level] || "#3498db";
                  
                  html += `<div style="margin-bottom:15px;border:1px solid #ddd;border-radius:4px;overflow:hidden;">
                            <div style="background:${riskColor};color:white;padding:8px;font-weight:bold;">
                              ${ip} - Risk: ${hostData.risk_level} (Score: ${hostData.risk_score}/100)
                            </div>
                            <div style="padding:10px;">`;
                  
                  // Open ports list
                  if (hostData.open_ports && hostData.open_ports.length > 0) {
                    html += `<div style="margin-bottom:10px;">
                              <div style="font-weight:bold;margin-bottom:3px;">Open Ports:</div>
                              <div style="display:flex;flex-wrap:wrap;">`;
                    
                    hostData.open_ports.forEach(portInfo => {
                      html += `<div style="background:#f1f1f1;padding:3px 8px;margin:2px;border-radius:3px;font-family:monospace;">${portInfo[0]}/${portInfo[1]}</div>`;
                    });
                    
                    html += `</div></div>`;
                  }
                  
                  // Vulnerabilities
                  if (hostData.vulnerabilities && hostData.vulnerabilities.length > 0) {
                    html += `<div>
                              <div style="font-weight:bold;margin-bottom:5px;">Vulnerabilities:</div>`;
                    
                    hostData.vulnerabilities.forEach(vuln => {
                      const severityColors = {
                        "Critical": "#e74c3c",
                        "High": "#e67e22",
                        "Medium": "#f1c40f",
                        "Low": "#3498db"
                      };
                      
                      const severityColor = severityColors[vuln.severity] || "#3498db";
                      
                      html += `<div style="margin-bottom:10px;border-left:4px solid ${severityColor};padding-left:10px;">
                                <div style="font-weight:bold;">${vuln.name}</div>
                                <div style="display:flex;margin:5px 0;">
                                  <div style="background:${severityColor};color:white;padding:2px 5px;border-radius:3px;margin-right:5px;font-size:12px;">${vuln.severity}</div>
                                  <div style="background:#34495e;color:white;padding:2px 5px;border-radius:3px;font-size:12px;">${vuln.cve}</div>
                                </div>
                                <div style="font-size:13px;margin-bottom:5px;">${vuln.description}</div>
                                <div style="font-family:monospace;font-size:12px;background:#f8f9fa;padding:5px;border-radius:3px;margin-bottom:5px;white-space:pre-wrap;">${vuln.details}</div>
                                <div style="background:#eaf2f8;padding:5px;border-radius:3px;font-size:12px;border-left:3px solid #3498db;">
                                  <strong>Remediation:</strong> ${vuln.remediation}
                                </div>
                              </div>`;
                    });
                    
                    html += `</div>`;
                  }
                  
                  html += `</div></div>`;
                }
              }
              
              // Update the pre element with the formatted HTML
              this.resultPre.innerHTML = html;
              this.resultLabel.innerText = "Result: ";
              return;
            }
            // For other template nodes, use standard JSON formatting
            else {
              // Convert the object to a formatted string with 2-space indentation
              displayValue = JSON.stringify(val, null, 2);
              
              // Create a pre element for formatting if it doesn't exist
              if (!this.resultPre) {
                this.resultPre = document.createElement("pre");
                this.resultPre.style.maxHeight = "300px";
                this.resultPre.style.overflow = "auto";
                this.resultPre.style.backgroundColor = "#f5f5f5";
                this.resultPre.style.padding = "8px";
                this.resultPre.style.border = "1px solid #ddd";
                this.resultPre.style.borderRadius = "4px";
                this.resultPre.style.marginTop = "5px";
                this.resultPre.style.fontSize = "12px";
                this.resultPre.style.fontFamily = "monospace";
                this.resultPre.style.whiteSpace = "pre-wrap";
                this.body.appendChild(this.resultPre);
              }
              
              // Update the pre element with the formatted JSON
              this.resultPre.textContent = displayValue;
              this.resultLabel.innerText = "Result: ";
              return;
            }
          } catch (e) {
            // Fall back to default if JSON.stringify fails
            displayValue = String(val);
          }
        }
        
        // For simple values, just show them in the label
        this.resultLabel.innerText = "Result: " + displayValue;
        
        // Remove the pre element if it exists for non-object values
        if (this.resultPre && this.resultPre.parentNode) {
          this.resultPre.parentNode.removeChild(this.resultPre);
          this.resultPre = null;
        }
      }
    }
  }
}

class Connection {
  constructor(diagram, fromNode, toNode, toIndex) {
    this.diagram = diagram;
    this.fromNode = fromNode;
    this.toNode = toNode;
    this.toIndex = toIndex;

    // Create an SVG path
    this.path = document.createElementNS("http://www.w3.org/2000/svg","path");
    this.path.setAttribute("stroke", "black");
    this.path.setAttribute("fill", "none");
    this.path.setAttribute("stroke-width", "2");
    diagram.svg.appendChild(this.path);

    // TODO: Add path removal listener to use remove()

    this.redraw();
  }

  redraw() {
    const diagRect = this.diagram.root.getBoundingClientRect();

    // we assume single output index=0, probably will expand this later
    let outTerm = this.fromNode.outputTerminals[0];
    let inTerm = this.toNode.inputTerminals[this.toIndex];
    if (!outTerm || !inTerm) return;

    let outRect = outTerm.getBoundingClientRect();
    let inRect = inTerm.getBoundingClientRect();

    let sx = outRect.left + outRect.width/2 - diagRect.left;
    let sy = outRect.top + outRect.height/2 - diagRect.top;
    let tx = inRect.left + inRect.width/2 - diagRect.left;
    let ty = inRect.top + inRect.height/2 - diagRect.top;

    let dx = (tx - sx)/2;
    let pathData = `M ${sx} ${sy} C ${sx+dx} ${sy}, ${tx-dx} ${ty}, ${tx} ${ty}`;
    this.path.setAttribute("d", pathData);
  }

  remove() {
    if (this.path && this.path.parentNode) {
      this.path.parentNode.removeChild(this.path);
    }
  }
}