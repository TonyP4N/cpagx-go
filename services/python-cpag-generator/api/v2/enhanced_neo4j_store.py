#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enhanced_neo4j_store.py
------------------------
Enhanced Neo4j storage module with task-specific features and error handling.
Supports task-based isolation, cleanup, and optimized batch operations.
"""

import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False


class EnhancedNeo4jStore:
    """Enhanced Neo4j storage with task isolation and cleanup"""
    
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        if not NEO4J_AVAILABLE:
            raise Exception("Neo4j driver not available. Install with: pip install neo4j")
        
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self.driver = None
        
    def __enter__(self):
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        
    def connect(self):
        """Establish Neo4j connection"""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Test connection
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1")
            print(f"Connected to Neo4j: {self.uri}")
        except Exception as e:
            raise Exception(f"Failed to connect to Neo4j: {e}")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            
    def ensure_constraints(self, label: str):
        """Ensure required constraints exist"""
        try:
            with self.driver.session(database=self.database) as session:
                # Drop old constraint if exists
                try:
                    session.run(f"DROP CONSTRAINT {label}_id")
                    print(f"Dropped old unique constraint on id for {label}")
                except Exception:
                    pass  # Constraint might not exist
                
                # Composite unique constraint on (id, task_id) to allow same node IDs across different tasks
                session.run(f"CREATE CONSTRAINT {label}_id_task IF NOT EXISTS FOR (n:{label}) REQUIRE (n.id, n.task_id) IS UNIQUE")
                
                # Index on task_id for efficient cleanup
                session.run(f"CREATE INDEX {label}_task_id IF NOT EXISTS FOR (n:{label}) ON (n.task_id)")
        except Exception as e:
            print(f"Warning: Failed to create constraints: {e}")
    
    def store_cpag_data(self, 
                       graph_data: Dict[str, Any], 
                       task_id: str,
                       label: str = "CPAGNode",
                       wipe_task: bool = False) -> Dict[str, Any]:
        """
        Store CPAG graph data with task isolation
        
        Args:
            graph_data: Graph data containing nodes and edges
            task_id: Task identifier for isolation
            label: Neo4j node label
            wipe_task: Whether to wipe existing data for this task
            
        Returns:
            Storage statistics
        """
        if not self.driver:
            raise Exception("Not connected to Neo4j")
        
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        
        if not nodes:
            return {'nodes_stored': 0, 'edges_stored': 0, 'status': 'no_data'}
        
        # Add task_id to all nodes for isolation and enhance with relationship metadata
        for node in nodes:
            node['task_id'] = task_id
            node['created_at'] = datetime.utcnow().isoformat()
            
            # Add relationship metadata for AND/OR logic
            if 'precondition_logic' in node:
                node['precondition_logic_type'] = node['precondition_logic'].get('type', 'simple')
            if 'dependencies' in node:
                node['dependency_count'] = len(node['dependencies'])
            if 'alternatives' in node:
                node['alternative_count'] = len(node['alternatives'])
        
        try:
            self.ensure_constraints(label)
            
            # Wipe existing data for this task if requested
            if wipe_task:
                self.cleanup_task_data(task_id, label)
            
            # Store nodes
            nodes_stored = self._batch_store_nodes(nodes, label)
            
            # Store edges
            edges_stored = self._batch_store_edges(edges, task_id, label)
            
            # Store metadata
            self._store_task_metadata(task_id, graph_data, label)
            
            return {
                'nodes_stored': nodes_stored,
                'edges_stored': edges_stored,
                'status': 'success',
                'task_id': task_id,
                'label': label
            }
            
        except Exception as e:
            return {
                'nodes_stored': 0,
                'edges_stored': 0,
                'status': 'failed',
                'error': str(e),
                'task_id': task_id
            }
    
    def _batch_store_nodes(self, nodes: List[Dict], label: str, batch_size: int = 1000) -> int:
        """Store nodes in batches"""
        total_stored = 0
        
        with self.driver.session(database=self.database) as session:
            for i in range(0, len(nodes), batch_size):
                batch = nodes[i:i + batch_size]
                
                cypher = f"""
                UNWIND $nodes AS node
                MERGE (n:{label} {{id: node.id, task_id: node.task_id}})
                SET n += node
                """
                
                result = session.run(cypher, nodes=batch)
                total_stored += len(batch)
        
        return total_stored
    
    def _batch_store_edges(self, edges: List[Dict], task_id: str, label: str, batch_size: int = 2000) -> int:
        """Store edges in batches with relationship type handling and AND/OR logic support"""
        if not edges:
            return 0
        
        # Group edges by relationship type
        edges_by_relation = {}
        for edge in edges:
            rel_type = self._sanitize_relationship_type(edge.get('relation', 'RELATES_TO'))
            edges_by_relation.setdefault(rel_type, []).append(edge)
        
        total_stored = 0
        
        with self.driver.session(database=self.database) as session:
            for rel_type, rel_edges in edges_by_relation.items():
                for i in range(0, len(rel_edges), batch_size):
                    batch = rel_edges[i:i + batch_size]
                    
                    # Enhanced cypher with logic_type property
                    cypher = f"""
                    UNWIND $edges AS edge
                    MATCH (s:{label} {{id: edge.source, task_id: $task_id}})
                    MATCH (t:{label} {{id: edge.target, task_id: $task_id}})
                    MERGE (s)-[r:{rel_type}]->(t)
                    SET r.logic_type = COALESCE(edge.logic_type, 'SEQUENTIAL'),
                        r.created_at = datetime(),
                        r.task_id = $task_id
                    """
                    
                    session.run(cypher, edges=batch, task_id=task_id)
                    total_stored += len(batch)
        
        return total_stored
    
    def _sanitize_relationship_type(self, rel_type: str) -> str:
        """Sanitize relationship type for Neo4j"""
        if not rel_type:
            return "RELATES_TO"
        
        # Convert to uppercase and replace invalid characters
        sanitized = rel_type.upper().replace(' ', '_').replace('-', '_')
        
        # Remove any non-alphanumeric characters except underscores
        import re
        sanitized = re.sub(r'[^A-Z0-9_]', '_', sanitized)
        
        # Ensure it starts with a letter
        if sanitized and not sanitized[0].isalpha():
            sanitized = 'REL_' + sanitized
        
        return sanitized or "RELATES_TO"
    
    def _store_task_metadata(self, task_id: str, graph_data: Dict, label: str):
        """Store task metadata for tracking"""
        metadata = {
            'task_id': task_id,
            'created_at': datetime.utcnow().isoformat(),
            'node_count': len(graph_data.get('nodes', [])),
            'edge_count': len(graph_data.get('edges', [])),
            'source_type': graph_data.get('source_type', 'unknown'),
            'processor_version': graph_data.get('processor_version', 'v2')
        }
        
        try:
            with self.driver.session(database=self.database) as session:
                cypher = f"""
                MERGE (m:CPAGMetadata {{task_id: $task_id}})
                SET m += $metadata
                """
                session.run(cypher, task_id=task_id, metadata=metadata)
        except Exception as e:
            print(f"Warning: Failed to store metadata: {e}")
    
    def cleanup_task_data(self, task_id: str, label: str) -> int:
        """Clean up all data for a specific task"""
        try:
            with self.driver.session(database=self.database) as session:
                # Delete nodes and their relationships
                result = session.run(f"""
                    MATCH (n:{label} {{task_id: $task_id}})
                    DETACH DELETE n
                    RETURN count(n) as deleted_count
                """, task_id=task_id)
                
                deleted_count = result.single()['deleted_count']
                
                # Delete metadata
                session.run("MATCH (m:CPAGMetadata {task_id: $task_id}) DELETE m", task_id=task_id)
                
                return deleted_count
        except Exception as e:
            print(f"Error cleaning up task data: {e}")
            return 0
    
    def get_task_data(self, task_id: str, label: str) -> Dict[str, Any]:
        """Retrieve all data for a specific task"""
        try:
            with self.driver.session(database=self.database) as session:
                # Get nodes
                nodes_result = session.run(f"""
                    MATCH (n:{label} {{task_id: $task_id}})
                    RETURN n
                """, task_id=task_id)
                
                nodes = [dict(record['n']) for record in nodes_result]
                
                # Get edges with enhanced relationship properties
                edges_result = session.run(f"""
                    MATCH (s:{label} {{task_id: $task_id}})-[r]->(t:{label} {{task_id: $task_id}})
                    RETURN s.id as source, type(r) as relation, t.id as target,
                           r.logic_type as logic_type, r.created_at as created_at
                """, task_id=task_id)
                
                edges = [dict(record) for record in edges_result]
                
                # Get metadata
                metadata_result = session.run("""
                    MATCH (m:CPAGMetadata {task_id: $task_id})
                    RETURN m
                """, task_id=task_id)
                
                metadata = None
                metadata_record = metadata_result.single()
                if metadata_record:
                    metadata = dict(metadata_record['m'])
                
                return {
                    'task_id': task_id,
                    'nodes': nodes,
                    'edges': edges,
                    'metadata': metadata,
                    'status': 'found' if nodes else 'not_found'
                }
                
        except Exception as e:
            return {
                'task_id': task_id,
                'nodes': [],
                'edges': [],
                'metadata': None,
                'status': 'error',
                'error': str(e)
            }
    
    def list_tasks(self, label: str) -> List[Dict[str, Any]]:
        """List all tasks with their basic information"""
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(f"""
                    MATCH (n:{label})
                    WHERE n.task_id IS NOT NULL
                    WITH n.task_id as task_id, count(n) as node_count, min(n.created_at) as created_at
                    OPTIONAL MATCH (m:CPAGMetadata {{task_id: task_id}})
                    RETURN task_id, node_count, created_at, 
                           m.source_type as source_type, m.processor_version as processor_version
                    ORDER BY created_at DESC
                """)
                
                return [dict(record) for record in result]
                
        except Exception as e:
            print(f"Error listing tasks: {e}")
            return []
    
    def cleanup_old_tasks(self, label: str, days_old: int = 7) -> int:
        """Clean up tasks older than specified days"""
        from datetime import timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        cutoff_iso = cutoff_date.isoformat()
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(f"""
                    MATCH (n:{label})
                    WHERE n.created_at < $cutoff_date
                    WITH n.task_id as task_id, count(n) as node_count
                    MATCH (old:{label} {{task_id: task_id}})
                    DETACH DELETE old
                    RETURN sum(node_count) as total_deleted
                """, cutoff_date=cutoff_iso)
                
                total_deleted = result.single()['total_deleted'] or 0
                
                # Clean up old metadata
                session.run("""
                    MATCH (m:CPAGMetadata)
                    WHERE m.created_at < $cutoff_date
                    DELETE m
                """, cutoff_date=cutoff_iso)
                
                return total_deleted
                
        except Exception as e:
            print(f"Error cleaning up old tasks: {e}")
            return 0


# Convenience functions
def store_cpag_to_neo4j(graph_data: Dict[str, Any], 
                       uri: str, 
                       user: str, 
                       password: str,
                       database: str = "neo4j",
                       label: str = "CPAGNode",
                       task_id: Optional[str] = None,
                       wipe_task: bool = False) -> Dict[str, Any]:
    """
    Convenience function to store CPAG data to Neo4j
    
    Args:
        graph_data: Graph data to store
        uri: Neo4j URI
        user: Neo4j username
        password: Neo4j password
        database: Neo4j database name
        label: Node label
        task_id: Task identifier
        wipe_task: Whether to wipe existing task data
        
    Returns:
        Storage result dictionary
    """
    if not task_id:
        from uuid import uuid4
        task_id = str(uuid4())
    
    try:
        with EnhancedNeo4jStore(uri, user, password, database) as store:
            return store.store_cpag_data(graph_data, task_id, label, wipe_task)
    except Exception as e:
        return {
            'nodes_stored': 0,
            'edges_stored': 0,
            'status': 'failed',
            'error': str(e),
            'task_id': task_id
        }


def get_task_graph_data(task_id: str,
                       uri: str,
                       user: str, 
                       password: str,
                       database: str = "neo4j",
                       label: str = "CPAGNode") -> Dict[str, Any]:
    """Retrieve graph data for a specific task"""
    try:
        with EnhancedNeo4jStore(uri, user, password, database) as store:
            return store.get_task_data(task_id, label)
    except Exception as e:
        return {
            'task_id': task_id,
            'nodes': [],
            'edges': [],
            'metadata': None,
            'status': 'error',
            'error': str(e)
        }


def cleanup_task_graph_data(task_id: str,
                           uri: str,
                           user: str,
                           password: str,
                           database: str = "neo4j", 
                           label: str = "CPAGNode") -> int:
    """Clean up graph data for a specific task"""
    try:
        with EnhancedNeo4jStore(uri, user, password, database) as store:
            return store.cleanup_task_data(task_id, label)
    except Exception as e:
        print(f"Error cleaning up task {task_id}: {e}")
        return 0