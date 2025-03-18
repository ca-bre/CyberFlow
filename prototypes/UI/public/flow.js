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
      }
    };
    
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

    // Diagram-level context menu (blank space => create nodes)
    this.contextMenu = document.createElement("ul");
    this.contextMenu.classList.add("context-menu");
    this.contextMenu.style.display = "none";
    document.body.appendChild(this.contextMenu);

    // Show context menu on right-click in blank area
    this.root.addEventListener("contextmenu", (e) => this.showContextMenu(e));

    // Hide menu on outside click
    document.addEventListener("click", () => {
      this.contextMenu.style.display = "none";
    });
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

  showContextMenu(e) {
    // Only show if user right-clicked blank space (the container or panDiv or svg)
    if (e.target !== this.root && e.target !== this.panDiv && e.target !== this.svg) {
      return; 
    }
    e.preventDefault();

    this.contextMenu.innerHTML = "";

    // 1) Standard Node for regular values
    const liStd = document.createElement("li");
    liStd.innerText = "Create Standard Node";
    liStd.onclick = (evt) => {
      evt.stopPropagation();
      this.createNode(e.clientX, e.clientY, "standard");
      this.contextMenu.style.display = "none";
    };
    this.contextMenu.appendChild(liStd);

    // 2) Template nodes
    Object.keys(this.templates).forEach((tplName) => {
      const li = document.createElement("li");
      li.innerText = tplName;
      li.onclick = (evt) => {
        evt.stopPropagation();
        this.createNode(e.clientX, e.clientY, tplName);
        this.contextMenu.style.display = "none";
      };
      this.contextMenu.appendChild(li);
    });

    this.contextMenu.style.left = e.clientX + "px";
    this.contextMenu.style.top = e.clientY + "px";
    this.contextMenu.style.display = "block";
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
    this.x = x;
    this.y = y;
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
        this.resultLabel.innerText = "Result: " + val;
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

  // Could use this to start with svg path removal
  // remove() {
  //   if (this.path && this.path.parentNode) {
  //     this.path.parentNode.removeChild(this.path);
  //   }
  // }
}
