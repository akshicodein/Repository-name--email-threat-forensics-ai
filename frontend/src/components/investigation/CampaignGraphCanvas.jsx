import React, { useState, useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Panel,
  useNodesState,
  useEdgesState,
  MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { 
  Network, 
  Layers, 
  Search, 
  Info, 
  X, 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  RefreshCw,
  Server,
  Globe,
  Mail,
  Dna,
  Database,
  Activity,
  Radio
} from 'lucide-react';
import { CustomEntityNode } from './CustomEntityNode';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

const nodeTypes = {
  customEntity: CustomEntityNode,
};

export function CampaignGraphCanvas({ intelligence, detection, forensics, id }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterType, setFilterType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const graphData = intelligence?.graph || { nodes: [], edges: [] };
  const ipIntelList = intelligence?.ip_intelligence || [];
  const domainIntelList = intelligence?.domain_intelligence || [];
  const relatedCases = intelligence?.related_cases || [];
  const campaign = intelligence?.campaign || {};

  // Edge relationship semantic mapping
  const getEdgeSemantics = (edgeType) => {
    const t = (edgeType || '').toLowerCase();
    if (t === 'contains' || t === 'has') return { label: edgeType, certainty: 'OBSERVED', color: '#06b6d4' };
    if (t === 'resolves_to' || t === 'belongs_to') return { label: edgeType, certainty: 'CONFIRMED', color: '#10b981' };
    if (t === 'related_to' || t === 'similar_to') return { label: edgeType, certainty: 'PROBABLE', color: '#8b5cf6' };
    if (t === 'associated_with' || t === 'correlates_with') return { label: edgeType, certainty: 'INFERRED', color: '#f97316' };
    return { label: edgeType || 'CONNECTED_TO', certainty: 'POTENTIAL', color: '#94a3b8' };
  };

  // Build React Flow nodes with hierarchical grid positions
  const { initialNodes, initialEdges } = useMemo(() => {
    const rawNodes = graphData.nodes || [];
    const rawEdges = graphData.edges || [];

    if (rawNodes.length === 0) {
      return { initialNodes: [], initialEdges: [] };
    }

    // Group nodes by layer for structured layout
    const layers = {
      Email: [],
      Domain: [],
      IP: [],
      ASN: [],
      AttackDNA: [],
      Case: [],
      Campaign: []
    };

    rawNodes.forEach((n) => {
      if (layers[n.type]) {
        layers[n.type].push(n);
      } else {
        layers.Domain.push(n);
      }
    });

    const flowNodes = [];
    const layerOrder = ['Email', 'Domain', 'IP', 'ASN', 'AttackDNA', 'Case', 'Campaign'];
    const ySpacing = 160;
    const xSpacing = 280;

    layerOrder.forEach((layerKey, layerIdx) => {
      const nodesInLayer = layers[layerKey] || [];
      const totalWidth = (nodesInLayer.length - 1) * xSpacing;
      const startX = 400 - totalWidth / 2;

      nodesInLayer.forEach((n, idx) => {
        let subtext = '';
        if (n.type === 'IP') {
          const intel = ipIntelList.find(i => i.ip === n.label);
          subtext = intel?.country ? `${intel.city || ''}, ${intel.country}` : 'Observed Network Node';
        } else if (n.type === 'Domain') {
          const dIntel = domainIntelList.find(d => d.domain === n.label);
          subtext = dIntel?.registrar || 'Domain Infrastructure';
        } else if (n.type === 'Campaign') {
          subtext = campaign?.summary ? `${Math.round((campaign.confidence || 0) * 100)}% Confidence Cluster` : 'Campaign Attribution';
        } else if (n.type === 'AttackDNA') {
          subtext = 'Behavioral Fingerprint';
        }

        flowNodes.push({
          id: n.id,
          type: 'customEntity',
          position: {
            x: startX + idx * xSpacing + (layerIdx % 2 === 1 ? 40 : 0),
            y: 50 + layerIdx * ySpacing,
          },
          data: {
            id: n.id,
            type: n.type,
            label: n.label,
            subtext,
            raw: n,
            certainty: n.type === 'Email' || n.type === 'IP' ? 'OBSERVED' : n.type === 'Campaign' ? 'INFERRED' : 'PROBABLE'
          },
        });
      });
    });

    const flowEdges = rawEdges.map((e, idx) => {
      const sem = getEdgeSemantics(e.type);
      return {
        id: `e-${e.from}-${e.to}-${idx}`,
        source: e.from,
        target: e.to,
        label: sem.label,
        type: 'smoothstep',
        animated: sem.certainty === 'INFERRED' || sem.certainty === 'PROBABLE',
        style: {
          stroke: sem.color,
          strokeWidth: 2,
          opacity: 0.85,
        },
        labelStyle: {
          fill: sem.color,
          fontFamily: 'monospace',
          fontSize: 10,
          fontWeight: 700,
        },
        labelBgStyle: {
          fill: '#0d121f',
          fillOpacity: 0.9,
          stroke: sem.color,
          strokeWidth: 1,
          rx: 4,
          ry: 4,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: sem.color,
          width: 16,
          height: 16,
        },
      };
    });

    return { initialNodes: flowNodes, initialEdges: flowEdges };
  }, [graphData, ipIntelList, domainIntelList, campaign]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Filter nodes based on selected filter or search
  const filteredNodes = useMemo(() => {
    return nodes.map((node) => {
      const matchesFilter = filterType === 'ALL' || node.data.type === filterType;
      const matchesSearch = !searchQuery || 
        node.data.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.data.type.toLowerCase().includes(searchQuery.toLowerCase());

      return {
        ...node,
        hidden: !matchesFilter || !matchesSearch,
      };
    });
  }, [nodes, filterType, searchQuery]);

  const onNodeClick = useCallback((event, node) => {
    setSelectedNode(node.data);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  if (initialNodes.length === 0) {
    return (
      <div className="p-12 rounded-2xl bg-slate-900/40 border border-slate-800 text-center font-mono space-y-3">
        <Network className="w-10 h-10 text-slate-600 mx-auto" />
        <h3 className="text-base font-bold text-slate-300">NO CORRELATION DATA AVAILABLE</h3>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          Campaign correlation requires available historical and entity relationship data from Member 3.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Top Toolbar & Filter Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-[#111726]/90 border border-slate-800 font-mono text-xs">
        <div className="flex items-center gap-2">
          <span className="text-slate-400 font-bold hidden sm:inline-block">FILTER ENTITIES:</span>
          <div className="flex flex-wrap gap-1">
            {['ALL', 'Email', 'Domain', 'IP', 'AttackDNA', 'Case', 'Campaign'].map((t) => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2.5 py-1 rounded text-[11px] font-bold transition-all ${
                  filterType === t
                    ? 'bg-cyan-500 text-slate-950 shadow-sm'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {t.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Search Field */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
          <input
            type="text"
            placeholder="Search entities in graph..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 pr-3 py-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 w-48 sm:w-60"
          />
        </div>
      </div>

      {/* Main React Flow Graph Container */}
      <div className="relative h-[620px] w-full rounded-2xl bg-[#090d16] border border-slate-800 shadow-2xl overflow-hidden">
        <ReactFlow
          nodes={filteredNodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onPaneClick={onPaneClick}
          nodeTypes={nodeTypes}
          fitView
          attributionPosition="bottom-left"
          minZoom={0.2}
          maxZoom={2.0}
        >
          <Background color="#1e293b" gap={24} size={1} />
          <Controls 
            className="!bg-[#111726] !border-slate-800 !text-slate-300 [&>button]:!bg-slate-900 [&>button]:!border-slate-800 [&>button:hover]:!bg-slate-800" 
          />
          <MiniMap
            className="!bg-[#0f1422] !border-slate-800 rounded-lg hidden md:block"
            nodeColor={(node) => {
              switch (node.data.type) {
                case 'Email': return '#06b6d4';
                case 'Domain': return '#f59e0b';
                case 'IP': return '#ef4444';
                case 'AttackDNA': return '#8b5cf6';
                case 'Campaign': return '#f97316';
                case 'Case': return '#10b981';
                default: return '#64748b';
              }
            }}
          />

          {/* Graph Legend Panel */}
          <Panel position="top-right" className="bg-[#111726]/95 border border-slate-800/90 p-3 rounded-xl backdrop-blur-md shadow-xl text-xs font-mono max-w-xs space-y-2 hidden lg:block">
            <span className="font-bold text-slate-300 uppercase block text-[10px] pb-1 border-b border-slate-800">
              RELATIONSHIP SEMANTICS
            </span>
            <div className="space-y-1.5 text-[11px]">
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span><span className="text-slate-300">OBSERVED</span> <span className="text-slate-400">(Direct Header Fact)</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span><span className="text-slate-300">CONFIRMED</span> <span className="text-slate-400">(DNS / Registry Record)</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-violet-400"></span><span className="text-slate-300">PROBABLE</span> <span className="text-slate-400">(Cosine Similarity Match)</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-orange-400"></span><span className="text-slate-300">INFERRED</span> <span className="text-slate-400">(Tactical Attribution)</span></div>
            </div>
          </Panel>
        </ReactFlow>

        {/* Selected Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute right-4 top-4 bottom-4 w-80 sm:w-96 bg-[#111726]/95 border border-slate-800 rounded-2xl p-5 backdrop-blur-xl shadow-2xl z-20 flex flex-col justify-between font-mono animate-fadeIn">
            <div className="space-y-4 overflow-y-auto pr-1">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Badge variant="info" size="xs">{selectedNode.type}</Badge>
                  <span className="text-xs font-bold text-slate-200">ENTITY INSPECTOR</span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div>
                <span className="text-[10px] text-slate-400 uppercase">IDENTIFIER / LABEL</span>
                <h4 className="text-sm font-bold text-cyan-300 break-all mt-0.5">
                  {selectedNode.label}
                </h4>
              </div>

              {/* Specific Entity Telemetry */}
              {selectedNode.type === 'IP' && (
                <div className="space-y-2.5 text-xs bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                  {(() => {
                    const intel = ipIntelList.find(i => i.ip === selectedNode.label);
                    return intel ? (
                      <>
                        <div><span className="text-slate-400 block text-[10px]">GEOLOCATION:</span> <span className="text-slate-200">{intel.city ? `${intel.city}, ` : ''}{intel.country || 'Not available'}</span></div>
                        <div><span className="text-slate-400 block text-[10px]">ISP / ASN:</span> <span className="text-slate-200">{intel.isp || 'Not available'} ({intel.asn || 'N/A'})</span></div>
                        <div><span className="text-slate-400 block text-[10px]">REPUTATION:</span> <span className="text-rose-400 font-bold">{intel.reputation || 'SUSPICIOUS'}</span></div>
                        <div><span className="text-slate-400 block text-[10px]">INFRASTRUCTURE:</span> <span className="text-slate-300">{intel.hosting_type || 'DataCenter / Cloud Node'}</span></div>
                      </>
                    ) : (
                      <div className="text-slate-400 italic">No external WHOIS enrichment for internal/hop IP.</div>
                    );
                  })()}
                </div>
              )}

              {selectedNode.type === 'Domain' && (
                <div className="space-y-2.5 text-xs bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                  {(() => {
                    const dIntel = domainIntelList.find(d => d.domain === selectedNode.label);
                    return dIntel ? (
                      <>
                        <div><span className="text-slate-400 block text-[10px]">REGISTRAR:</span> <span className="text-slate-200">{dIntel.registrar || 'Not available'}</span></div>
                        <div><span className="text-slate-400 block text-[10px]">CREATED DATE:</span> <span className="text-slate-200">{dIntel.created_date || 'Not available'}</span></div>
                        <div><span className="text-slate-400 block text-[10px]">A-RECORDS:</span> <span className="text-cyan-300">{dIntel.a_records ? dIntel.a_records.join(', ') : 'None'}</span></div>
                        <div><span className="text-slate-400 block text-[10px]">REPUTATION:</span> <span className="text-amber-400 font-bold">{dIntel.reputation || 'POOR'}</span></div>
                      </>
                    ) : (
                      <div className="text-slate-400 italic">Domain extracted from message headers.</div>
                    );
                  })()}
                </div>
              )}

              {selectedNode.type === 'Campaign' && (
                <div className="space-y-2.5 text-xs bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                  <div><span className="text-slate-400 block text-[10px]">CONFIDENCE:</span> <span className="text-orange-400 font-bold">{Math.round((campaign.confidence || 0.85) * 100)}%</span></div>
                  <div><span className="text-slate-400 block text-[10px]">CAMPAIGN DOSSIER:</span> <span className="text-slate-200 font-sans text-xs">{campaign.summary || 'Coordinated infrastructure pattern.'}</span></div>
                </div>
              )}

              {selectedNode.type === 'AttackDNA' && (
                <div className="space-y-2 text-xs bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">BEHAVIORAL FINGERPRINT:</span>
                  <p className="text-xs text-slate-300 font-sans">
                    Quantized feature representation correlating header anomalies, domain deception, and linguistic coercion.
                  </p>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between">
              <span>Certainty: {selectedNode.certainty || 'OBSERVED'}</span>
              <span>Source: Member 3 Graph</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
