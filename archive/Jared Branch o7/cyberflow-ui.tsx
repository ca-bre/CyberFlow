import React, { useState, useEffect, useRef } from 'react';
import { ArrowDownCircle, Settings, Play, Zap, Shield, AlertTriangle, Cpu, Database, FileText, ChevronRight, HelpCircle, X, Check, Loader } from 'lucide-react';

const CyberFlowApp = () => {
  const [workspace, setWorkspace] = useState([]);
  const [palette, setPalette] = useState([]);
  const [reports, setReports] = useState([]);
  const [isDragging, setIsDragging] = useState(false);
  const [draggedBlock, setDraggedBlock] = useState(null);
  const [connections, setConnections] = useState([]);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [activeConnection, setActiveConnection] = useState(null);
  const [connectingFrom, setConnectingFrom] = useState(null);
  const [hoveredSocket, setHoveredSocket] = useState(null);
  const [blockConfigs, setBlockConfigs] = useState({});
  const [running, setRunning] = useState(false);
  const [activeBlocks, setActiveBlocks] = useState([]);
  const [showHelp, setShowHelp] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [scanResults, setScanResults] = useState({});
  const [vulnerabilityResults, setVulnerabilityResults] = useState({});
  const [attackResults, setAttackResults] = useState({});
  const [scanStatus, setScanStatus] = useState("idle");
  const [vulnStatus, setVulnStatus] = useState("idle");
  const [attackStatus, setAttackStatus] = useState("idle");
  
  const workspaceRef = useRef(null);
  let notificationIdCounter = useRef(0);

  // Initialize palette of available blocks
  useEffect(() => {
    setPalette([
      {
        id: 'port-scanner',
        type: 'scanner',
        title: 'Port Scanner',
        color: '#4CAF50',
        icon: <Cpu size={16} />,
        description: 'Scans target IP addresses for open ports',
        inputs: [],
        outputs: ['scan-results'],
        config: {
          target: '127.0.0.1',
          ports: '1-1000'
        }
      },
      {
        id: 'vulnerability-scanner',
        type: 'vulnerability',
        title: 'Vulnerability Scanner',
        color: '#FFC107',
        icon: <Shield size={16} />,
        description: 'Analyzes open ports for known vulnerabilities',
        inputs: ['scan-results'],
        outputs: ['vulnerability-results'],
        config: {}
      },
      {
        id: 'attack-module',
        type: 'attack',
        title: 'Attack Module',
        color: '#F44336',
        icon: <Zap size={16} />,
        description: 'Simulates attacks on detected vulnerabilities',
        inputs: ['vulnerability-results'],
        outputs: ['attack-results'],
        config: {
          executeAttacks: false
        }
      },
      {
        id: 'report-generator',
        type: 'report',
        title: 'Report Generator',
        color: '#2196F3',
        icon: <FileText size={16} />,
        description: 'Creates detailed reports of findings',
        inputs: ['scan-results', 'vulnerability-results', 'attack-results'],
        outputs: [],
        config: {
          format: 'html',
          includeDetails: true
        }
      },
      {
        id: 'data-storage',
        type: 'storage',
        title: 'Data Storage',
        color: '#9C27B0',
        icon: <Database size={16} />,
        description: 'Saves results to a file or database',
        inputs: ['scan-results', 'vulnerability-results', 'attack-results'],
        outputs: [],
        config: {
          storageType: 'file',
          path: './reports'
        }
      }
    ]);
  }, []);

  // Fetch existing reports on load
  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const response = await fetch('/api/reports');
      if (response.ok) {
        const data = await response.json();
        setReports(data);
      }
    } catch (error) {
      addNotification('Error fetching reports: ' + error.message, 'error');
    }
  };

  // Poll for status updates when operations are running
  useEffect(() => {
    let interval;
    
    if (scanStatus === 'running' || vulnStatus === 'running' || attackStatus === 'running') {
      interval = setInterval(() => {
        if (scanStatus === 'running') pollScanStatus();
        if (vulnStatus === 'running') pollVulnerabilityStatus();
        if (attackStatus === 'running') pollAttackStatus();
      }, 1000);
    }
    
    return () => clearInterval(interval);
  }, [scanStatus, vulnStatus, attackStatus]);

  const pollScanStatus = async () => {
    try {
      const response = await fetch('/api/scan/status');
      if (response.ok) {
        const data = await response.json();
        
        // Update the progress in the active block
        updateBlockProgress('port-scanner', data.progress || 0);
        
        if (data.status === 'completed') {
          setScanStatus('completed');
          setScanResults(data.results);
          addNotification('Port scan completed successfully!', 'success');
          
          // Automatically proceed to vulnerability assessment if connected
          const scannerBlock = workspace.find(block => block.type === 'scanner');
          const vulnBlock = workspace.find(block => block.type === 'vulnerability');
          
          if (scannerBlock && vulnBlock) {
            const isConnected = connections.some(
              conn => conn.fromId === scannerBlock.id && conn.toId === vulnBlock.id
            );
            
            if (isConnected) {
              runVulnerabilityAssessment(data.results);
            }
          }
        } else if (data.status === 'error') {
          setScanStatus('error');
          addNotification(`Error during scan: ${data.error}`, 'error');
        }
      }
    } catch (error) {
      addNotification('Error checking scan status: ' + error.message, 'error');
    }
  };

  const pollVulnerabilityStatus = async () => {
    try {
      const response = await fetch('/api/assess/status');
      if (response.ok) {
        const data = await response.json();
        
        // Update the progress in the active block
        updateBlockProgress('vulnerability-scanner', data.progress || 0);
        
        if (data.status === 'completed') {
          setVulnStatus('completed');
          setVulnerabilityResults(data.results);
          addNotification('Vulnerability assessment completed!', 'success');
          
          // Check if we should automatically run attack module
          const vulnBlock = workspace.find(block => block.type === 'vulnerability');
          const attackBlock = workspace.find(block => block.type === 'attack');
          
          if (vulnBlock && attackBlock) {
            const isConnected = connections.some(
              conn => conn.fromId === vulnBlock.id && conn.toId === attackBlock.id
            );
            
            if (isConnected) {
              runAttacks(data.results);
            }
          }
        } else if (data.status === 'error') {
          setVulnStatus('error');
          addNotification(`Error during vulnerability assessment: ${data.error}`, 'error');
        }
      }
    } catch (error) {
      addNotification('Error checking vulnerability status: ' + error.message, 'error');
    }
  };

  const pollAttackStatus = async () => {
    try {
      const response = await fetch('/api/attack/status');
      if (response.ok) {
        const data = await response.json();
        
        // Update the progress in the active block
        updateBlockProgress('attack-module', data.progress || 0);
        
        if (data.status === 'completed') {
          setAttackStatus('completed');
          setAttackResults(data.results);
          addNotification('Attack simulation completed!', 'success');
          
          // Run report generation if connected
          const attackBlock = workspace.find(block => block.type === 'attack');
          const reportBlock = workspace.find(block => block.type === 'report');
          
          if (attackBlock && reportBlock) {
            const isConnected = connections.some(
              conn => conn.fromId === attackBlock.id && conn.toId === reportBlock.id
            );
            
            if (isConnected) {
              generateReport();
            }
          }
        } else if (data.status === 'error') {
          setAttackStatus('error');
          addNotification(`Error during attack simulation: ${data.error}`, 'error');
        }
      }
    } catch (error) {
      addNotification('Error checking attack status: ' + error.message, 'error');
    }
  };

  const addNotification = (message, type = 'info') => {
    const id = notificationIdCounter.current++;
    setNotifications(prev => [...prev, { id, message, type, timestamp: Date.now() }]);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  };

  const updateBlockProgress = (blockType, progress) => {
    setWorkspace(prev => 
      prev.map(block => {
        if (block.type === blockType.replace('-', '')) {
          return { ...block, progress };
        }
        return block;
      })
    );
  };

  const handleDragStart = (e, block, isPalette = false) => {
    e.preventDefault();
    const rect = e.currentTarget.getBoundingClientRect();
    const offsetX = e.clientX - rect.left;
    const offsetY = e.clientY - rect.top;
    
    setDragOffset({ x: offsetX, y: offsetY });
    
    if (isPalette) {
      // Create a new instance from palette
      const newBlock = {
        ...block,
        id: `${block.id}-${Date.now()}`, // Generate unique ID
        x: e.clientX - offsetX,
        y: e.clientY - offsetY,
        status: 'idle',
        progress: 0
      };
      setDraggedBlock(newBlock);
    } else {
      // Move existing block
      setDraggedBlock({ ...block });
    }
    
    setIsDragging(true);
  };

  const handleDragMove = (e) => {
    if (!isDragging || !draggedBlock) return;
    
    const workspaceRect = workspaceRef.current.getBoundingClientRect();
    const x = Math.max(0, e.clientX - workspaceRect.left - dragOffset.x);
    const y = Math.max(0, e.clientY - workspaceRect.top - dragOffset.y);
    
    setDraggedBlock(prev => ({ ...prev, x, y }));
  };

  const handleDragEnd = () => {
    if (!isDragging || !draggedBlock) return;
    
    // If this block wasn't in the workspace before, add it
    if (!workspace.find(block => block.id === draggedBlock.id)) {
      setWorkspace(prev => [...prev, draggedBlock]);
      // Initialize block config
      setBlockConfigs(prev => ({
        ...prev,
        [draggedBlock.id]: { ...draggedBlock.config }
      }));
    } else {
      // Update position of existing block
      setWorkspace(prev => 
        prev.map(block => 
          block.id === draggedBlock.id 
            ? { ...block, x: draggedBlock.x, y: draggedBlock.y }
            : block
        )
      );
    }
    
    setIsDragging(false);
    setDraggedBlock(null);
  };

  const startConnection = (fromBlock, outputType) => {
    setConnectingFrom({ blockId: fromBlock.id, outputType });
    setActiveConnection({ fromX: 0, fromY: 0, toX: 0, toY: 0 });
  };

  const updateActiveConnection = (e) => {
    if (!connectingFrom) return;
    
    const workspaceRect = workspaceRef.current.getBoundingClientRect();
    const fromBlock = workspace.find(block => block.id === connectingFrom.blockId);
    
    if (!fromBlock) return;
    
    // Calculate from position (output socket)
    const outputs = document.querySelectorAll(`[data-block-id="${fromBlock.id}"] .output-socket`);
    let fromSocket;
    
    for (const socket of outputs) {
      if (socket.getAttribute('data-type') === connectingFrom.outputType) {
        fromSocket = socket;
        break;
      }
    }
    
    if (!fromSocket) return;
    
    const fromRect = fromSocket.getBoundingClientRect();
    const fromX = fromRect.left + fromRect.width / 2 - workspaceRect.left;
    const fromY = fromRect.top + fromRect.height / 2 - workspaceRect.top;
    
    // To position is the mouse cursor
    const toX = e.clientX - workspaceRect.left;
    const toY = e.clientY - workspaceRect.top;
    
    setActiveConnection({ fromX, fromY, toX, toY });
  };

  const completeConnection = (toBlock, inputType) => {
    if (!connectingFrom) return;
    
    // Check if connection is valid (output type matches input type)
    if (connectingFrom.outputType !== inputType) {
      addNotification('Cannot connect incompatible blocks', 'error');
      cancelConnection();
      return;
    }
    
    // Check if connection already exists
    const exists = connections.some(
      conn => 
        conn.fromId === connectingFrom.blockId && 
        conn.toId === toBlock.id &&
        conn.type === inputType
    );
    
    if (exists) {
      cancelConnection();
      return;
    }
    
    // Add new connection
    setConnections(prev => [...prev, {
      id: `conn-${Date.now()}`,
      fromId: connectingFrom.blockId,
      toId: toBlock.id,
      type: inputType
    }]);
    
    // Reset connection state
    setConnectingFrom(null);
    setActiveConnection(null);
  };

  const cancelConnection = () => {
    setConnectingFrom(null);
    setActiveConnection(null);
  };

  const removeBlock = (blockId) => {
    // Remove block
    setWorkspace(prev => prev.filter(block => block.id !== blockId));
    
    // Remove any connections to/from this block
    setConnections(prev => prev.filter(
      conn => conn.fromId !== blockId && conn.toId !== blockId
    ));
    
    // Remove any config
    setBlockConfigs(prev => {
      const newConfigs = { ...prev };
      delete newConfigs[blockId];
      return newConfigs;
    });
  };

  const removeConnection = (connectionId) => {
    setConnections(prev => prev.filter(conn => conn.id !== connectionId));
  };

  const updateBlockConfig = (blockId, key, value) => {
    setBlockConfigs(prev => ({
      ...prev,
      [blockId]: {
        ...prev[blockId],
        [key]: value
      }
    }));
  };

  const runPortScan = async (blockId) => {
    const block = workspace.find(b => b.id === blockId);
    if (!block || block.type !== 'scanner') return;
    
    // Get the configuration for this block
    const config = blockConfigs[blockId] || {};
    const target = config.target || '127.0.0.1';
    const ports = config.ports || '1-1000';
    
    // Mark block as running
    setWorkspace(prev => 
      prev.map(b => 
        b.id === blockId 
          ? { ...b, status: 'running', progress: 0 } 
          : b
      )
    );
    
    setScanStatus('running');
    setActiveBlocks(prev => [...prev, blockId]);
    
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, ports })
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to start scan');
      }
      
      addNotification(`Started port scan on ${target}`, 'info');
    } catch (error) {
      addNotification('Error starting scan: ' + error.message, 'error');
      setWorkspace(prev => 
        prev.map(b => 
          b.id === blockId 
            ? { ...b, status: 'error', progress: 0 } 
            : b
        )
      );
      setScanStatus('error');
      setActiveBlocks(prev => prev.filter(id => id !== blockId));
    }
  };

  const runVulnerabilityAssessment = async (scanResults) => {
    // Find the vulnerability scanner block
    const vulnBlock = workspace.find(block => block.type === 'vulnerability');
    if (!vulnBlock) {
      addNotification('No vulnerability scanner block in workspace', 'error');
      return;
    }

    // Mark block as running
    setWorkspace(prev => 
      prev.map(b => 
        b.id === vulnBlock.id 
          ? { ...b, status: 'running', progress: 0 } 
          : b
      )
    );
    
    setVulnStatus('running');
    setActiveBlocks(prev => [...prev, vulnBlock.id]);

    try {
      const response = await fetch('/api/assess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_results: scanResults })
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to start vulnerability assessment');
      }
      
      addNotification('Started vulnerability assessment', 'info');
    } catch (error) {
      addNotification('Error starting vulnerability assessment: ' + error.message, 'error');
      setWorkspace(prev => 
        prev.map(b => 
          b.id === vulnBlock.id 
            ? { ...b, status: 'error', progress: 0 } 
            : b
        )
      );
      setVulnStatus('error');
      setActiveBlocks(prev => prev.filter(id => id !== vulnBlock.id));
    }
  };

  const runAttacks = async (vulnerabilityResults) => {
    // Find the attack module block
    const attackBlock = workspace.find(block => block.type === 'attack');
    if (!attackBlock) {
      addNotification('No attack module block in workspace', 'error');
      return;
    }

    // Mark block as running
    setWorkspace(prev => 
      prev.map(b => 
        b.id === attackBlock.id 
          ? { ...b, status: 'running', progress: 0 } 
          : b
      )
    );
    
    setAttackStatus('running');
    setActiveBlocks(prev => [...prev, attackBlock.id]);

    try {
      const response = await fetch('/api/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability_results: vulnerabilityResults })
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to start attack simulation');
      }
      
      addNotification('Started attack simulation', 'info');
    } catch (error) {
      addNotification('Error starting attacks: ' + error.message, 'error');
      setWorkspace(prev => 
        prev.map(b => 
          b.id === attackBlock.id 
            ? { ...b, status: 'error', progress: 0 } 
            : b
        )
      );
      setAttackStatus('error');
      setActiveBlocks(prev => prev.filter(id => id !== attackBlock.id));
    }
  };

  const generateReport = async () => {
    // Fetch latest reports after all operations are complete
    fetchReports();
    addNotification('Generated report with all findings', 'success');
  };

  const runWorkflow = () => {
    // Find the start of our workflow (typically the scanner)
    const scannerBlock = workspace.find(block => block.type === 'scanner');
    
    if (!scannerBlock) {
      addNotification('Workflow must include a port scanner block', 'error');
      return;
    }
    
    setRunning(true);
    runPortScan(scannerBlock.id);
  };

  const stopWorkflow = () => {
    setRunning(false);
    setActiveBlocks([]);
    setScanStatus('idle');
    setVulnStatus('idle');
    setAttackStatus('idle');
    
    // Reset block statuses
    setWorkspace(prev => 
      prev.map(block => ({ ...block, status: 'idle', progress: 0 }))
    );
  };

  const handleSocketMouseOver = (e, blockId, socketType, isInput) => {
    setHoveredSocket({ blockId, socketType, isInput });
  };

  const handleSocketMouseOut = () => {
    setHoveredSocket(null);
  };

  const handleSocketClick = (e, block, socketType, isInput) => {
    e.stopPropagation();
    
    if (connectingFrom) {
      if (isInput) {
        // Complete the connection
        completeConnection(block, socketType);
      } else {
        // Cancel current connection and start a new one
        cancelConnection();
        startConnection(block, socketType);
      }
    } else if (!isInput) {
      // Start a new connection from an output
      startConnection(block, socketType);
    }
  };

  const getSocketPosition = (blockId, socketType, isInput) => {
    const socketEl = document.querySelector(
      `[data-block-id="${blockId}"] ${isInput ? '.input-socket' : '.output-socket'}[data-type="${socketType}"]`
    );
    
    if (!socketEl) return { x: 0, y: 0 };
    
    const rect = socketEl.getBoundingClientRect();
    const workspaceRect = workspaceRef.current.getBoundingClientRect();
    
    return {
      x: rect.left + rect.width / 2 - workspaceRect.left,
      y: rect.top + rect.height / 2 - workspaceRect.top
    };
  };

  // Draw SVG connection path between blocks
  const getConnectionPath = (fromId, toId, type) => {
    const fromPos = getSocketPosition(fromId, type, false);
    const toPos = getSocketPosition(toId, type, true);
    
    const deltaX = toPos.x - fromPos.x;
    const controlPointOffset = Math.min(Math.abs(deltaX) * 0.5, 100);
    
    return `M ${fromPos.x} ${fromPos.y} C ${fromPos.x + controlPointOffset} ${fromPos.y}, ${toPos.x - controlPointOffset} ${toPos.y}, ${toPos.x} ${toPos.y}`;
  };

  // Get the path for the active connection being drawn
  const getActiveConnectionPath = () => {
    if (!activeConnection) return '';
    
    const { fromX, fromY, toX, toY } = activeConnection;
    const deltaX = toX - fromX;
    const controlPointOffset = Math.min(Math.abs(deltaX) * 0.5, 100);
    
    return `M ${fromX} ${fromY} C ${fromX + controlPointOffset} ${fromY}, ${toX - controlPointOffset} ${toY}, ${toX} ${toY}`;
  };

  const renderConfig = (blockId) => {
    const block = workspace.find(b => b.id === blockId);
    if (!block) return null;
    
    const config = blockConfigs[blockId] || {};
    
    switch (block.type) {
      case 'scanner':
        return (
          <div className="p-4">
            <div className="mb-4">
              <label className="block mb-2 text-sm font-medium">Target IP:</label>
              <input
                className="w-full p-2 border rounded"
                type="text"
                value={config.target || ''}
                onChange={e => updateBlockConfig(blockId, 'target', e.target.value)}
                placeholder="e.g. 192.168.1.1"
              />
            </div>
            <div className="mb-4">
              <label className="block mb-2 text-sm font-medium">Port Range:</label>
              <input
                className="w-full p-2 border rounded"
                type="text"
                value={config.ports || ''}
                onChange={e => updateBlockConfig(blockId, 'ports', e.target.value)}
                placeholder="e.g. 1-1000,3389"
              />
            </div>
          </div>
        );
      
      case 'attack':
        return (
          <div className="p-4">
            <div className="mb-4">
              <label className="flex items-center text-sm font-medium">
                <input
                  type="checkbox"
                  className="mr-2"
                  checked={config.executeAttacks || false}
                  onChange={e => updateBlockConfig(blockId, 'executeAttacks', e.target.checked)}
                />
                Execute actual attacks (caution!)
              </label>
              <p className="mt-1 text-xs text-gray-500">
                Only enable in controlled test environments with proper authorization.
              </p>
            </div>
          </div>
        );
      
      default:
        return (
          <div className="p-4 text-sm">
            <p>No configuration options available for this block.</p>
          </div>
        );
    }
  };

  const renderBlock = (block) => {
    // Status indicator color
    let statusColor = 'bg-gray-500';
    if (block.status === 'running') statusColor = 'bg-blue-500';
    else if (block.status === 'completed') statusColor = 'bg-green-500';
    else if (block.status === 'error') statusColor = 'bg-red-500';
    
    // Get block color from palette
    const paletteItem = palette.find(item => item.type === block.type);
    const blockColor = paletteItem ? paletteItem.color : '#999';
    
    return (
      <div 
        className="absolute shadow-lg rounded-lg overflow-hidden select-none bg-white"
        style={{ 
          left: block.x, 
          top: block.y, 
          width: 250,
          border: `2px solid ${blockColor}`,
          zIndex: isDragging && draggedBlock?.id === block.id ? 1000 : 10
        }}
        data-block-id={block.id}
        onMouseDown={(e) => handleDragStart(e, block)}
        key={block.id}
      >
        {/* Header */}
        <div 
          className="px-3 py-2 text-white font-bold flex items-center justify-between cursor-move"
          style={{ backgroundColor: blockColor }}
        >
          <div className="flex items-center">
            {paletteItem?.icon && <span className="mr-2">{paletteItem.icon}</span>}
            {block.title}
          </div>
          <div className="flex items-center">
            <span className={`w-3 h-3 rounded-full mr-2 ${statusColor}`}></span>
            <button 
              className="hover:bg-red-700 hover:bg-opacity-30 p-1 rounded"
              onClick={() => removeBlock(block.id)}
            >
              <X size={16} />
            </button>
          </div>
        </div>
        
        {/* Input sockets */}
        <div className="px-4 pt-3 pb-2">
          {block.inputs?.map(input => (
            <div 
              key={`${block.id}-in-${input}`}
              className="flex items-center mb-2"
            >
              <div 
                className={`input-socket w-3 h-3 rounded-full border border-gray-500 bg-white mr-2 cursor-pointer
                  ${(hoveredSocket?.blockId === block.id && hoveredSocket?.socketType === input && hoveredSocket?.isInput) ? 'ring-2 ring-blue-500' : ''}
                  ${connectingFrom && !connectingFrom.isInput ? 'hover:ring-2 hover:ring-blue-500' : ''}
                `}
                data-type={input}
                onMouseOver={(e) => handleSocketMouseOver(e, block.id, input, true)}
                onMouseOut={handleSocketMouseOut}
                onClick={(e) => handleSocketClick(e, block, input, true)}
              ></div>
              <span className="text-xs text-gray-600">{input}</span>
            </div>
          ))}
        </div>
        
        {/* Block content */}
        <div className="p-4 pt-2 border-t border-gray-200">
          <p className="text-sm text-gray-600 mb-2">{paletteItem?.description}</p>
          
          {/* Configuration controls */}
          {renderConfig(block.id)}
          
          {/* Progress bar (visible when running) */}
          {block.status === 'running' && (
            <div className="h-2 bg-gray-200 rounded mt-2">
              <div 
                className="h-full bg-blue-500 rounded"
                style={{ width: `${block.progress || 0}%` }}
              ></div>
            </div>
          )}
          
          {/* Run button for scanner (start of workflow) */}
          {block.type === 'scanner' && block.status !== 'running' && (
            <button
              className="mt-2 px-4 py-1 bg-green-600 text-white rounded text-sm flex items-center justify-center w-full disabled:bg-gray-400"
              onClick={() => runPortScan(block.id)}
              disabled={running}
            >
              <Play size={14} className="mr-1" /> Run Scan
            </button>
          )}
        </div>
        
        {/* Output sockets */}
        <div className="px-4 pb-3 pt-2 border-t border-gray-200">
          {block.outputs?.map(output => (
            <div 
              key={`${block.id}-out-${output}`}
              className="flex items-center justify-end mb-2"
            >
              <span className="text-xs text-gray-600">{output}</span>
              <div 
                className={`output-socket w-3 h-3 rounded-full border border-gray-500 bg-white ml-2 cursor-pointer
                  ${(hoveredSocket?.blockId === block.id && hoveredSocket?.socketType === output && !hoveredSocket?.isInput) ? 'ring-2 ring-blue-500' : ''}
                `}
                data-type={output}
                onMouseOver={(e) => handleSocketMouseOver(e, block.id, output, false)}
                onMouseOut={handleSocketMouseOut}
                onClick={(e) => handleSocketClick(e, block, output, false)}
              ></div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="h-screen flex flex-col bg-gray-100">
      {/* Top toolbar */}
      <div className="bg-gray-800 text-white p-3 flex items-center justify-between">
        <div className="flex items-center">
          <Cpu size={24} className="mr-2" />
          <h1 className="text-xl font-bold">CyberFlow</h1>
          <span className="ml-2 text-xs bg-blue-500 px-2 py-1 rounded-full">Educational Edition</span>
        </div>
        
        <div className="flex space-x-4">
          <button 
            className={`px-4 py-1 rounded flex items-center ${running ? 'bg-red-600' : 'bg-green-600'}`}
            onClick={running ? stopWorkflow : runWorkflow}
          >
            {running ? (
              <>
                <X size={16} className="mr-1" /> Stop
              </>
            ) : (
              <>
                <Play size={16} className="mr-1" /> Run All
              </>
            )}
          </button>
          
          <button 
            className="px-4 py-1 bg-gray-700 rounded flex items-center"
            onClick={() => setShowHelp(!showHelp)}
          >
            <HelpCircle size={16} className="mr-1" /> Help
          </button>
        </div>
      </div>
      
      <div className="flex flex-1 overflow-hidden">
        {/* Left sidebar (block palette) */}
        <div className="w-64 bg-gray-100 border-r border-gray-300 overflow-y-auto">
          <div className="p-4">
            <h2 className="font-bold mb-3 text-gray-700">Block Palette</h2>
            
            {palette.map(item => (
              <div 
                key={item.id}
                className="mb-3 bg-white rounded-lg shadow p-3 cursor-grab"
                onMouseDown={(e) => handleDragStart(e, item, true)}
              >
                <div className="flex items-center mb-1">
                  <span className="p-1 rounded mr-2" style={{ backgroundColor: item.color }}>
                    {item.icon}
                  </span>
                  <span className="font-medium">{item.title}</span>
                </div>
                <p className="text-xs text-gray-600">{item.description}</p>
              </div>
            ))}
          </div>
        </div>
        
        {/* Main workspace */}
        <div 
          ref={workspaceRef}
          className="flex-1 relative bg-white overflow-auto"
          onMouseMove={(e) => {
            handleDragMove(e);
            updateActiveConnection(e);
          }}
          onMouseUp={handleDragEnd}
          onClick={cancelConnection}
        >
          {/* SVG for connections */}
          <svg 
            className="absolute top-0 left-0 w-full h-full pointer-events-none" 
            style={{ zIndex: 5 }}
          >
            {/* Existing connections */}
            {connections.map(conn => (
              <g key={conn.id}>
                <path
                  d={getConnectionPath(conn.fromId, conn.toId, conn.type)}
                  stroke={palette.find(item => 
                    item.type === workspace.find(b => b.id === conn.fromId)?.type
                  )?.color || '#666'}
                  strokeWidth="2"
                  fill="none"
                />
                {/* Connection removal target */}
                <path
                  d={getConnectionPath(conn.fromId, conn.toId, conn.type)}
                  stroke="transparent" 
                  strokeWidth="10"
                  fill="none"
                  style={{ cursor: 'pointer', pointerEvents: 'all' }}
                  onClick={(e) => {
                    e.stopPropagation();
                    removeConnection(conn.id);
                  }}
                />
              </g>
            ))}
            
            {/* Active connection being drawn */}
            {activeConnection && (
              <path
                d={getActiveConnectionPath()}
                stroke="#3498db"
                strokeWidth="2"
                strokeDasharray="5,5"
                fill="none"
              />
            )}
          </svg>
          
          {/* Blocks */}
          {workspace.map(block => renderBlock(block))}
          
          {/* Dragged block (preview) */}
          {isDragging && draggedBlock && (
            <div 
              className="absolute shadow-lg rounded-lg overflow-hidden opacity-70 pointer-events-none"
              style={{ 
                left: draggedBlock.x, 
                top: draggedBlock.y, 
                width: 250,
                border: `2px solid ${palette.find(item => item.type === draggedBlock.type)?.color || '#999'}`,
                zIndex: 1000
              }}
            >
              <div 
                className="px-3 py-2 text-white font-bold"
                style={{ backgroundColor: palette.find(item => item.type === draggedBlock.type)?.color || '#999' }}
              >
                {draggedBlock.title}
              </div>
              <div className="p-4 bg-white">
                <p className="text-sm text-gray-600">
                  {palette.find(item => item.type === draggedBlock.type)?.description}
                </p>
              </div>
            </div>
          )}
          
          {/* Empty state message */}
          {workspace.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-gray-500">
              <ArrowDownCircle size={48} className="mb-2" />
              <p>Drag blocks from the palette to start building your security workflow</p>
            </div>
          )}
        </div>
        
        {/* Right sidebar */}
        <div className="w-64 bg-gray-100 border-l border-gray-300 overflow-y-auto">
          <div className="p-4">
            <h2 className="font-bold mb-3 text-gray-700">Reports</h2>
            
            {reports.length === 0 ? (
              <p className="text-sm text-gray-500">No reports available yet. Run your workflow to generate reports.</p>
            ) : (
              <div className="space-y-2">
                {reports.slice(0, 10).map(report => (
                  <a 
                    key={report.path}
                    href={report.path} 
                    target="_blank" 
                    rel="noreferrer"
                    className="block p-2 bg-white rounded border border-gray-300 text-sm hover:bg-blue-50"
                  >
                    <div className="font-medium">{report.filename}</div>
                    <div className="text-xs text-gray-500">
                      {new Date(report.created * 1000).toLocaleString()}
                    </div>
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* Notification area */}
      <div className="fixed bottom-4 right-4 space-y-2 z-50">
        {notifications.map(notification => (
          <div 
            key={notification.id}
            className={`p-3 rounded shadow-lg text-white flex items-center max-w-md animate-fadeIn
              ${notification.type === 'error' ? 'bg-red-600' : 
                notification.type === 'success' ? 'bg-green-600' : 'bg-blue-600'}`}
          >
            {notification.type === 'error' ? (
              <AlertTriangle size={16} className="mr-2" />
            ) : notification.type === 'success' ? (
              <Check size={16} className="mr-2" />
            ) : (
              <Loader size={16} className="mr-2" />
            )}
            <span>{notification.message}</span>
          </div>
        ))}
      </div>
      
      {/* Help overlay */}
      {showHelp && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-lg max-w-2xl w-full max-h-screen overflow-y-auto">
            <div className="border-b border-gray-200 p-4 flex justify-between items-center">
              <h2 className="text-xl font-bold">CyberFlow Help</h2>
              <button 
                className="text-gray-500 hover:text-gray-700"
                onClick={() => setShowHelp(false)}
              >
                <X size={20} />
              </button>
            </div>
            
            <div className="p-6">
              <h3 className="font-bold text-lg mb-2">Getting Started</h3>
              <p className="mb-4">CyberFlow is a visual programming tool for learning cybersecurity concepts through hands-on experimentation.</p>
              
              <h3 className="font-bold text-lg mb-2">Building a Workflow</h3>
              <ol className="list-decimal pl-6 mb-4 space-y-2">
                <li>Drag blocks from the palette on the left into the workspace</li>
                <li>Configure each block by setting parameters</li>
                <li>Connect blocks by clicking on an output socket and then an input socket</li>
                <li>Run the workflow by clicking the "Run All" button or individual block "Run" buttons</li>
              </ol>
              
              <h3 className="font-bold text-lg mb-2">Available Blocks</h3>
              <div className="space-y-3 mb-4">
                <div>
                  <div className="flex items-center">
                    <span className="p-1 rounded mr-2 bg-green-500 text-white">
                      <Cpu size={16} />
                    </span>
                    <span className="font-medium">Port Scanner</span>
                  </div>
                  <p className="text-sm text-gray-600 ml-8">Scans IP addresses to find open ports and services</p>
                </div>
                
                <div>
                  <div className="flex items-center">
                    <span className="p-1 rounded mr-2 bg-yellow-500 text-white">
                      <Shield size={16} />
                    </span>
                    <span className="font-medium">Vulnerability Scanner</span>
                  </div>
                  <p className="text-sm text-gray-600 ml-8">Analyzes open ports for known vulnerabilities</p>
                </div>
                
                <div>
                  <div className="flex items-center">
                    <span className="p-1 rounded mr-2 bg-red-500 text-white">
                      <Zap size={16} />
                    </span>
                    <span className="font-medium">Attack Module</span>
                  </div>
                  <p className="text-sm text-gray-600 ml-8">Simulates attacks on detected vulnerabilities</p>
                </div>
              </div>
              
              <h3 className="font-bold text-lg mb-2">Tips</h3>
              <ul className="list-disc pl-6 mb-4 space-y-2">
                <li>Always get permission before scanning systems you don't own</li>
                <li>Use the "Stop" button to cancel a running workflow</li>
                <li>View results in the Reports panel on the right</li>
                <li>Remove connections by clicking on the line between blocks</li>
                <li>Remove blocks by clicking the X in the top-right corner</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CyberFlowApp;
