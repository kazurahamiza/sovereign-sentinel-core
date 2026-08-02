use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum NodeType {
    Process(u32), // PID
    File(String),
    Network(String), // IP Address
}

#[derive(Debug, Clone)]
pub struct EdgeAction {
    pub action_type: String, // e.g., "SPAWNED", "INJECTED", "WRITTEN_TO"
    pub timestamp: u64,
}

pub struct ThreatGraph {
    pub adjacency_list: HashMap<NodeType, Vec<(NodeType, EdgeAction)>>,
}

impl ThreatGraph {
    pub fn new() -> Self {
        Self {
            adjacency_list: HashMap::new(),
        }
    }

    /// Appends a new relationship edge to the threat graph
    pub fn add_edge(&mut self, source: NodeType, target: NodeType, action: &str, timestamp: u64) {
        let edge = EdgeAction {
            action_type: action.to_string(),
            timestamp,
        };
        self.adjacency_list
            .entry(source)
            .or_insert_with(Vec::new)
            .push((target, edge));
    }

    /// Traces the full process execution lineage back to the root parent process
    pub fn trace_root_cause(&self, node: &NodeType, visited: &mut HashSet<NodeType>) {
        if visited.contains(node) {
            return;
        }
        visited.insert(node.clone());

        println!("[GRAPH] Analyzing Lineage Node: {:?}", node);

        for (parent, edges) in &self.adjacency_list {
            for (child, action) in edges {
                if child == node {
                    println!("  └── Ancestor Found: {:?} via Action '{}'", parent, action.action_type);
                    self.trace_root_cause(parent, visited);
                }
            }
        }
    }
}
