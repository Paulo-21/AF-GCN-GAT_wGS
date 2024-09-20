//use ::graph::page_rank::PageRankConfig;
//use ::graph::prelude::{page_rank, DirectedCsrGraph, GraphBuilder};
//use ::graph::prelude::{page_rank, DirectedCsrGraph, DirectedDegrees, Graph, GraphBuilder, PageRankConfig};
use graph::ArgumentationFramework;
use pyo3::prelude::*;
use simple_pagerank::Pagerank;
use std::io::{BufRead, BufReader};
//use std::time::Instant;
use std::collections::HashMap;
use std::fs;
use std::hash::BuildHasherDefault;
use std::collections::HashSet;
use ahash::AHasher;
//use hashbrown::HashMap;

mod gradualsemantics;
mod simple_grounded_semantics_solver2;
mod graph;

use gradualsemantics::{bbs, categorizer, euclidian_based, fuzzing, perso};//, counting};
use gradualsemantics::card_based;
use gradualsemantics::no_self_att_hcat;
use gradualsemantics::max_based;
use rustworkx_core::petgraph;
use rustworkx_core::centrality::eigenvector_centrality;
use rustworkx_core::coloring::greedy_node_color;

fn _reading_file_for_rustworkx (file_path : &str) -> Vec<(u32, u32)> {
    let first_line = get_first_line(file_path);
    match first_line.trim().starts_with("p af") {
        true => {
            reading_cnf_for_rustworkx(file_path)
        },
        false => {
            reading_apx_for_rustworkx(file_path)
        }
    }
}
#[pyfunction]
fn reading_file_for_dgl (file_path : &str) -> PyResult<(Vec<u32>, Vec<u32>, u32)> {
    let fl = get_first_line(file_path);
    let first_line = fl.trim();
    if first_line.starts_with("p af") {
        return Ok(reading_cnf_for_dgl(file_path).unwrap());
    }
    else if first_line.starts_with("arg(") {
        return Ok(reading_apx_for_dgl(file_path));
    }
    else {
        return Ok(reading_tgf_for_dgl(file_path));
    }
}
fn get_first_line(file_path : &str ) -> String {
    let file = match fs::File::open(&file_path) {
        Ok(file) => file,
        Err(_) => panic!("Unable to read title from {:?}", &file_path),
    };
    let mut buffer = BufReader::new(file);
    let mut first_line = String::new();
    let _ = buffer.read_line(&mut first_line);

    first_line
}

#[pyfunction]
fn compute_eigenvector_centrality(file_path : &str, iter:usize, tol :f64) -> PyResult<Vec<f64>> {
    let edge = reading_cnf_for_rustworkx(file_path);

    let g = petgraph::graph::DiGraph::<u32, ()>::from_edges(&edge);
    //let start = Instant::now();
    let eig = eigenvector_centrality(&g,  |_| {Ok::<f64,f64>(1.)}, Some(iter), Some(tol));
    //println!("Computed in {} ms", start.elapsed().as_millis());
    return Ok(eig.unwrap().unwrap());
}

#[pyfunction]
fn reading_cnf( file_path : &str) -> PyResult<(Vec<i32>, Vec<(i32,i32)>)> {
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let mut content_iter = contents.trim().split('\n');
    let first_line = content_iter.next().unwrap();
    let iter: Vec<&str> = first_line.split_ascii_whitespace().collect();
    let nb_arg = iter[2].parse::<i32>().unwrap();
    let mut args = Vec::with_capacity(nb_arg as usize);
    for i in 0..nb_arg {
        args.push(i);
    }
    let mut att = Vec::with_capacity(contents.capacity());
    for line in content_iter {
        if !line.starts_with('#') && (!line.trim().eq("")) {
            let (attacker,target) = parse_cnfattack_line(line);
            att.push((attacker-1, target-1));
        }
    }
    Ok((args,att))
}
fn reading_cnf_for_rustworkx( file_path : &str) -> Vec<(u32, u32)> {
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file {}");
    let content_iter = contents.trim().split('\n').skip(1);
    let mut att_edge = Vec::with_capacity(contents.capacity());
    for line in content_iter {
        if !line.starts_with('#') {
            let t = parse_cnfattack_line_usigned(line);
            att_edge.push((t.0-1, t.1-1));
        }
    }
    att_edge
}

fn reading_tgf_af_arg_id(file_path : &str, arg_id: &str) -> (ArgumentationFramework, usize, usize) {
    let mut index = 0;
    let mut tot_edges = 0;
    let mut index_map: HashMap<_, usize, BuildHasherDefault<AHasher>> = HashMap::default();
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n');
    let mut first = true;
    let mut af = ArgumentationFramework::new(1);
    for line in a {
        if line.starts_with('#') || line.trim() == "" { continue; }
        let mut spl = line.split_ascii_whitespace();
        let arg1 = spl.next().unwrap();
        let mut att_line = false;
        let mut arg2 = "";
        if let Some(a) = spl.next() {
            att_line = true;
            arg2 = a;
        }
        if !att_line {
            index_map.insert(arg1, index);
            index+=1;
        }
        else {
            if first {
                first = false;
                af = ArgumentationFramework::new(index_map.len());
            }
            tot_edges+=1;
            let attacker = *index_map.get(arg1).unwrap();
            let target = *index_map.get(arg2).unwrap();
            af.add_attack_wo_sub(attacker, target);
        }
    }
    (af, *index_map.get(arg_id).unwrap(), tot_edges)
}
fn reading_tgf_af(file_path : &str) -> ArgumentationFramework {
    let mut index = 0;
    let mut index_map: HashMap<_, usize, BuildHasherDefault<AHasher>> = HashMap::default();
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n');
    let mut first = true;
    let mut af = ArgumentationFramework::new(1);
    for line in a {
        if line.starts_with('#') || line.trim() == "" { continue; }
        let mut spl = line.split_ascii_whitespace();
        let arg1 = spl.next().unwrap();
        let mut att_line = false;
        let mut arg2 = "";
        if let Some(a) = spl.next() {
            att_line = true;
            arg2 = a;
        }
        if !att_line {
            index_map.insert(arg1, index);
            index+=1;
        }
        else {
            if first {
                first = false;
                af = ArgumentationFramework::new(index_map.len());
            }
            let attacker = *index_map.get(arg1).unwrap();
            let target = *index_map.get(arg2).unwrap();
            af.add_attack_wo_sub(attacker, target);
        }
    }
    af
}
fn reading_tgf_for_dgl(file_path : &str) -> (Vec<u32>,Vec<u32>, u32) {
    let mut index = 0;
    let mut index_map: HashMap<_, usize, BuildHasherDefault<AHasher>> = HashMap::default();
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n');
    let mut sources = Vec::new();
    let mut targets = Vec::new();
    for line in a {
        if line.starts_with('#') || line.trim() == "" { continue; }
        let mut spl = line.split_ascii_whitespace();
        let arg1 = spl.next().unwrap();
        let mut att_line = false;
        let mut arg2 = "";
        if let Some(a) = spl.next() {
            att_line = true;
            arg2 = a;
        }
        if !att_line {
            index_map.insert(arg1, index);
            index+=1;
        }
        else {
            let attacker = *index_map.get(arg1).unwrap();
            let target = *index_map.get(arg2).unwrap();
            sources.push(attacker as u32);
            targets.push(target as u32);
        }
    }
    (sources, targets, index_map.len() as u32)
}
fn get_tgf_hashmap_of(file_path : &str) -> HashMap<String, usize, BuildHasherDefault<AHasher>> {
    let mut index = 0;
    let mut index_map: HashMap<String, usize, BuildHasherDefault<AHasher>> = HashMap::default();
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n');
    for line in a {
        if line.starts_with('#') || line.trim() == "" { continue; }
        let mut spl = line.split_ascii_whitespace();
        let arg1 = spl.next().unwrap();
        let mut att_line = false;
        if let Some(_a) = spl.next() {
            att_line = true;
        }
        if !att_line {
            let c = String::from(arg1);
            index_map.insert(c, index);
            index+=1;
        }
        else {
            break;
        }
    }
    index_map
}
#[pyfunction]
fn  read_lars_solution_dc(sol_path : &str, instance_path : &str) -> PyResult<Vec<f32>> {
    let file = fs::read_to_string(sol_path).expect("File no found");
    let index_map = get_tgf_hashmap_of(instance_path);
    let mut target : Vec<f32> = vec![0.; index_map.len()];
    let mut in_contener = false;
    let mut in_array = false;
    let mut current_arg = String::new();
    for c in file.chars() {
        match c {
            '[' => {
                if !in_contener { in_contener = true; }
                else { in_array = true; }
            },
            ']' => {
                if in_array && in_contener { in_array = false; }
                else { in_contener = false; }
            },
            ',' => {
                if current_arg.is_empty() {
                    continue;
                }
                let id = match index_map.get(current_arg.as_str()) {
                    Some(id) => *id,
                    None => {
                        //println!("{}", current_arg);
                        panic!("NO FOUND ARGUMENT");
                    }
                };
                target[id] = 1.0;
                current_arg.clear();
            },
            _ => {
                if c == ' ' { continue; }
                current_arg.push(c);
            }
        }
    }
    Ok(target)
}
#[pyfunction]
fn read_lars_solution_ds(sol_path : &str, instance_path : &str) -> PyResult<Vec<f32>> {
    let file = fs::read_to_string(sol_path).expect("File no found");
    let index_map = get_tgf_hashmap_of(instance_path);
    let mut target : Vec<f32> = vec![0.; index_map.len()];
    let mut current_set : HashSet<usize> = HashSet::new();
    let mut in_contener = false;
    let mut in_array = false;
    let mut first_iter = true;
    let mut final_set: HashSet<usize> = HashSet::new();
    let mut current_arg = String::new();
    for c in file.chars() {
        match c {
            '[' => {
                if !in_contener { in_contener = true; }
                else if !in_array {
                    in_array = true;
                    current_set = HashSet::new();
                }
            },
            ']' => {
                if in_array && in_contener {
                    in_array = false;

                    let id = if let Some(i) = index_map.get(current_arg.as_str()) { *i }
                    else { continue; };

                    current_set.insert(id);
                    current_arg.clear();
                    if !first_iter {
                        let inter : Vec<&usize> = final_set.intersection(&current_set).collect();
                        let mut newhashset = HashSet::with_capacity(inter.capacity());
                        for internumber in inter {
                            newhashset.insert(*internumber);
                        }
                        final_set = newhashset
                    }
                    else {
                        first_iter = false;
                        final_set = current_set;
                        current_set = HashSet::new();
                    }
                    current_set.clear();
                }
                else if !in_array {
                    break;
                }
            },
            ',' => {
                if in_array {
                    let id = *index_map.get(current_arg.as_str()).unwrap();
                    current_set.insert(id);
                    current_arg.clear();
                }
            },
            _ => {
                if c.is_ascii_alphabetic() || c.is_ascii_digit() { 
                    current_arg.push(c);
                }
            }
        }
    }
    ////println!("{:?}", final_set);
    for ds_index in final_set {
        target[ds_index] = 1.0;
    }
    Ok(target)
}

fn compute_pagerank(edges : &[(u32,u32)], n : usize, convergence : f64) -> Pagerank<u32> {
    let mut pr: Pagerank<u32> = Pagerank::<u32>::with_capacity(n);
    for i in 0..n as u32 {
        pr.add_node(i);
    }
    for edge in edges {
        pr.add_edge(edge.0, edge.1);
    }
    pr.calculate_with_convergence(convergence);
    pr
}
#[pyfunction]
fn compute_only_gs(file_path : &str) -> PyResult<Vec<[f64;4]>> {
    let af = reading_file_af(file_path);
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    for node in 0..af.nb_argument {
        raw_features.push([
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node]
        ]);
    }
    Ok(raw_features)
}

#[pyfunction]
fn compute_only_gs_w_gr(file_path : &str) -> PyResult<Vec<[f64;5]>> {
    let af = reading_file_af(file_path);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    for node in 0..af.nb_argument {
        raw_features.push([
            gr[node],
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node]
        ]);
    }
    Ok(raw_features)
}
#[pyfunction]
fn compute_only_gs_w_gr_sa_ed(file_path : &str) -> PyResult<Vec<[f64;8]>> {
    let af = reading_file_af(file_path);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 -1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            gr[node],
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node],
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
        ]);
    }
    Ok(raw_features)
}
#[pyfunction]
fn compute_only_gs_w_gr_sa_ed_eb(file_path : &str) -> PyResult<Vec<[f64;9]>> {
    let af = reading_file_af(file_path);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    let hcat = categorizer::solve(&af);
    let eucli = euclidian_based::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 -1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            gr[node],
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node],
            eucli[node],
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
        ]);
    }
    Ok(raw_features)
}
fn get_minmax(bbs : &Vec<f64>) -> (f64, f64) {
    let mut max = f64::MIN;
    let mut min = f64::MAX;
    for b in bbs {
        if *b > max { max = *b; }
        if *b < min { min = *b; }
    }
    /*let max = bbs.iter().max_by(|a, b| a.total_cmp(b)).unwrap();
    let min = bbs.iter().min_by(|a, b| a.total_cmp(b)).unwrap();*/
    (max, min)
}

#[pyfunction]
fn compute_only_gs_w_gr_sa_ed_perso(file_path : &str) -> PyResult<Vec<[f64;9]>> {
    let af = reading_file_af(file_path);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    let hcat = categorizer::solve(&af);
    //let perso = perso::solve(&af, &gr, &hcat);
    let bbs = bbs::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let (bbs_max, bbs_min) = get_minmax(&bbs);
    //println!("{} {}", bbs_max, bbs_min);
    let n = af.nb_argument as f64 -1.;
    let mut mi = f64::MAX;
    let mut ma = f64::MIN;
    for node in 0..af.nb_argument {
        raw_features.push([
            gr[node],
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node],
            //perso[node],
            ((bbs[node] - bbs_min) / (bbs_max - bbs_min) )* ((bbs_max - bbs_min) + bbs_min),
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
            ]);
        if bbs_max == bbs_min {
           let a = raw_features.last_mut().unwrap();
            a[5] = 0.;
        }

        ma = ma.max((bbs[node] - bbs_min) / (bbs_max - bbs_min));
        mi = mi.min((bbs[node] - bbs_min) / (bbs_max - bbs_min));
    }
    //println!("{} {}", ma, mi);
    Ok(raw_features)
}
fn perso_score(af : &ArgumentationFramework, node : usize, gr : &Vec<f64>, hcat: &Vec<f64>) -> f64 {
    let mut sum_score_attacker = 0.;
    let basic_score = 0.5;
    let mut final_score = 1.;
    for  attacker in &af.af_attacker[node] {
		if gr[*attacker] == 1. || hcat[*attacker] >= 0.8 {
            sum_score_attacker = 0.;
            break;
        }
        let mut maxdeff =0.;
        for deffender in af.af_attacker[*attacker].iter() {
            let mut a = basic_score;
            if hcat[*deffender] > 0.7  { a = hcat[*deffender] };
            if gr[*deffender] == 1. { a = 1.; }
            if a > maxdeff {
                maxdeff = a;
            }
        }
        sum_score_attacker += maxdeff;
    }
    if af.af_attacker[node].len() > 0 {
        final_score = sum_score_attacker/af.af_attacker[node].len() as f64;
    }
    final_score
}
#[pyfunction]
fn compute_only_gs_w_gr_sa_ed_perso_mod(file_path : &str) -> PyResult<Vec<[f64;9]>> {
    let af = reading_file_af(file_path);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 -1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            gr[node],
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node],
            perso_score(&af, node, &gr, &hcat),
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
        ]);
    }
    Ok(raw_features)
}
#[pyfunction]
fn compute_only_gs_w_gr_sa_ed_fuzz(file_path : &str) -> PyResult<Vec<[f64;9]>> {
    let af = reading_file_af(file_path);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let fuzzing = fuzzing::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 -1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            gr[node],
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node],
            fuzzing[node],
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
        ]);
    }
    Ok(raw_features)
}
#[pyfunction]
fn special(file_path : &str, arg_id : &str/*, format : u8*/) -> PyResult<(Vec<[f64;11]>,Vec<usize>, Vec<usize>, u32, usize,  u8,)> {
    let iter = 10000;
    let tol = 0.0001;
    let (af, arg_id, tot_edges) = reading_file_af_arg(file_path, arg_id);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    if gr[arg_id] == 1. {
		return Ok((Vec::new(),Vec::new(), Vec::new(), 0,0, 1));
	}
	if gr[arg_id] == 0. {
        return Ok((Vec::new(),Vec::new(), Vec::new(), 0,0, 0));
    }
    //let start = Instant::now();
    let hcat = categorizer::solve(&af);
    //println!("SEM {}", start.elapsed().as_secs());
    //let start = Instant::now();
    let card = card_based::solve(&af);
    //println!("SEM {}", start.elapsed().as_secs());
    //let start = Instant::now();
    let noselfatt = no_self_att_hcat::solve(&af);
    //println!("SEM {}", start.elapsed().as_secs());
    //let start = Instant::now();
    let maxbased = max_based::solve(&af);
    //println!("SEM {}", start.elapsed().as_secs());
    let mut edges = Vec::with_capacity(tot_edges);
    let mut att1 = Vec::with_capacity(tot_edges);
    let mut att2 = Vec::with_capacity(tot_edges);
    for (source, atts) in af.af_attackee.iter().enumerate() {
        for target in atts {
            edges.push((source as u32, *target as u32));
            att1.push(source);
            att2.push(*target);
        }
    }
    let mut g: petgraph::prelude::Graph<u32, ()> = petgraph::graph::DiGraph::<u32, ()>::new();
    g.reserve_exact_nodes(af.nb_argument);
    for i in 0..af.nb_argument as u32 {
        g.add_node(i);
    }
    g.extend_with_edges(&edges);
    let page_rank = compute_pagerank(&edges, g.node_count(), 0.001);
    //let start = Instant::now();
    let eig = eigenvector_centrality(&g,  |_| {Ok::<f64,f64>(1.)}, Some(iter), Some(tol)).unwrap().unwrap();
    //println!("EIG {}", start.elapsed().as_secs());
    let coloring = greedy_node_color(&g);
    let mut raw_features = Vec::with_capacity(g.node_count());
    let n = g.node_count() as f64 - 1.;
    for node in 0..g.node_count() {
        raw_features.push([
            coloring[node] as f64, page_rank.get_score(node as u32).unwrap() as f64,
            (af.af_attackee[node].len() + af.af_attackee[node].len() ) as f64 /n, eig[node],
            af.af_attackee[node].len() as f64, af.af_attacker[node].len() as f64,
            hcat[node], card[node], noselfatt[node],
            maxbased[node], gr[node]
        ]);
    }

    return Ok((raw_features, att1, att2, g.node_count() as u32, arg_id, 2));
}

#[pyfunction]
fn special_gs(file_path : &str, arg_id : &str/*, format : u8*/) -> PyResult<(Vec<[f64;8]>, u32, usize,  u8,)> {
    let (af, arg_id, _tot_edges) = reading_file_af_arg(file_path, arg_id);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    if gr[arg_id] == 1. {
		return Ok((Vec::new(), 0,0, 1));
	}
	if gr[arg_id] == 0. {
        return Ok((Vec::new(), 0,0, 0));
    }
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 - 1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            gr[node],
            hcat[node],
            card[node],
            noselfatt[node],
            maxbased[node],
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
        ]);
    }

    return Ok((raw_features, af.nb_argument as u32, arg_id, 2));
}
#[pyfunction]
fn special_gs_for_gat(file_path : &str, arg_id : &str) -> PyResult<(Vec<[f64;8]>, Vec<usize>, Vec<usize>, u32, usize,  u8,)> {
    let (af, arg_id, tot_edges) = reading_file_af_arg(file_path, arg_id);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    if gr[arg_id] == 1. {
		return Ok((Vec::new(), Vec::new(), Vec::new(), 0,0, 1));
	}
	if gr[arg_id] == 0. {
        return Ok((Vec::new(), Vec::new(), Vec::new(), 0,0, 0));
    }
    let mut att1 = Vec::with_capacity(tot_edges);
    let mut att2 = Vec::with_capacity(tot_edges);
    for (source, atts) in af.af_attackee.iter().enumerate() {
        for target in atts {
            att1.push(source);
            att2.push(*target);
        }
    }
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 - 1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            hcat[node],
            card[node], 
            noselfatt[node],
            maxbased[node],
            gr[node],
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
        ]);
    }

    return Ok((raw_features, att1, att2, af.nb_argument as u32, arg_id, 2));
}
#[pyfunction]
fn _special_gs_perso(file_path : &str, arg_id : &str) -> PyResult<(Vec<[f64;8]>, Vec<usize>, Vec<usize>, u32, usize,  u8,)> {
    let (af, arg_id, tot_edges) = reading_file_af_arg(file_path, arg_id);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    if gr[arg_id] == 1. {
		return Ok((Vec::new(), Vec::new(), Vec::new(), 0,0, 1));
	}
	if gr[arg_id] == 0. {
        return Ok((Vec::new(), Vec::new(), Vec::new(), 0,0, 0));
    }
    let mut att1 = Vec::with_capacity(tot_edges);
    let mut att2 = Vec::with_capacity(tot_edges);
    for (source, atts) in af.af_attackee.iter().enumerate() {
        for target in atts {
            att1.push(source);
            att2.push(*target);
        }
    }
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);
    let _perso = perso::solve(&af, &gr, &hcat);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 - 1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            hcat[node],
            card[node], 
            noselfatt[node],
            maxbased[node],
            gr[node],
            af.af_attackee[node].len() as f64 / n,
            af.af_attacker[node].len() as f64 / n,
            if af.af_attacker[node].contains(&node) { 0.} else { 0.5 },
        ]);
    }

    return Ok((raw_features, att1, att2, af.nb_argument as u32, arg_id, 2));
}

#[pyfunction]
fn special_only(file_path : &str, arg_id : &str/*, format : u8*/) -> PyResult<(usize, u8)> {
    let (af, arg_id, _tot_edges) = reading_file_af_arg(file_path, arg_id);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    if gr[arg_id] == 1. {
		return Ok((arg_id, 1));
    }
	else if gr[arg_id] == 0. {
        return Ok((arg_id, 0));
    }
    Ok((arg_id, 2))
}
#[pyfunction]
fn special_wo_gs(file_path : &str, arg_id : &str/*, format : u8*/) -> PyResult<(Vec<[f64;6]>,Vec<usize>, Vec<usize>, u32, usize,  u8,)> {
    let iter = 10000;
    let tol = 0.00001;
    let (af, arg_id, tot_edges) = reading_file_af_arg(file_path, arg_id);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    if gr[arg_id] == 1. {
		return Ok((Vec::new(),Vec::new(), Vec::new(), 0,0, 1));
	}
	if gr[arg_id] == 0. {
        return Ok((Vec::new(),Vec::new(), Vec::new(), 0,0, 0));
    }
    /*
    let hcat = categorizer::solve(&af);
    let card = card_based::solve(&af);
    let noselfatt = no_self_att_hcat::solve(&af);
    let maxbased = max_based::solve(&af);*/
    let mut edges = Vec::with_capacity(tot_edges);
    let mut att1 = Vec::with_capacity(tot_edges);
    let mut att2 = Vec::with_capacity(tot_edges);
    for (source, atts) in af.af_attackee.iter().enumerate() {
        for target in atts {
            edges.push((source as u32, *target as u32));
            att1.push(source);
            att2.push(*target);
        }
    }
    let mut g: petgraph::prelude::Graph<u32, ()> = petgraph::graph::DiGraph::<u32, ()>::new();
    g.reserve_exact_nodes(af.nb_argument);
    for i in 0..af.nb_argument as u32 {
        g.add_node(i);
    }
    g.extend_with_edges(&edges);
    let page_rank = compute_pagerank(&edges, g.node_count(), 0.001);
    let eig = eigenvector_centrality(&g,  |_| {Ok::<f64,f64>(1.)}, Some(iter), Some(tol)).unwrap().unwrap();
    let coloring = greedy_node_color(&g);
    let mut raw_features = Vec::with_capacity(g.node_count());
    let n = g.node_count() as f64 - 1.;
    for node in 0..g.node_count() {
        raw_features.push([
            coloring[node] as f64, page_rank.get_score(node as u32).unwrap() as f64,
            (af.af_attackee[node].len() + af.af_attackee[node].len() ) as f64 /n, eig[node],
            af.af_attackee[node].len() as f64, af.af_attacker[node].len() as f64,
        ]);
    }

    return Ok((raw_features, att1, att2, g.node_count() as u32, arg_id, 2));
}
#[pyfunction]
fn compute_features(file_path : &str, iter:usize, tol : f64)-> PyResult<Vec<[f64;11]>> {
    //let start1 = Instant::now();
    let af = reading_file_af(file_path);
    let mut edges = Vec::with_capacity(af.nb_argument*2);
    let mut att1 = Vec::with_capacity(af.nb_argument*2);
    let mut att2 = Vec::with_capacity(af.nb_argument*2);
    for (source, atts) in af.af_attackee.iter().enumerate() {
        for target in atts {
            edges.push((source as u32, *target as u32));
            att1.push(source);
            att2.push(*target);
        }
    }
    
    let (hcat, card, noselfatt, maxbased, gr,af ) = reading_cnf_with_semantics_and_af(file_path);
    let mut g: petgraph::prelude::Graph<u32, ()> = petgraph::graph::DiGraph::<u32, ()>::new();
    g.reserve_exact_nodes(hcat.len());
    for i in 0..hcat.len() as u32 {
        g.add_node(i);
    }
    g.extend_with_edges(&edges);
    let page_rank = compute_pagerank(&edges, g.node_count(), 0.001);
    let eig = eigenvector_centrality(&g,  |_| {Ok::<f64,f64>(1.)}, Some(iter), Some(tol)).unwrap().unwrap();
    let coloring = greedy_node_color(&g);
    let mut raw_features = Vec::with_capacity(g.node_count());
    let n = g.node_count() as f64 -1.;
    for node in 0..g.node_count() {
        raw_features.push([
            coloring[node] as f64, page_rank.get_score(node as u32).unwrap() as f64,
            (af.af_attackee[node].len() + af.af_attackee[node].len() ) as f64 /n, eig[node],
            af.af_attackee[node].len() as f64, af.af_attacker[node].len() as f64,
            hcat[node], card[node], noselfatt[node],
            maxbased[node], gr[node]    
        ]);
    }
    //println!("Inside Rust {} ms", start1.elapsed().as_millis());
    
    Ok(raw_features)
}
#[pyfunction]
fn compute_features_extend(file_path : &str)-> PyResult<Vec<[f64;8]>> {
    
    let (hcat, card, noselfatt, maxbased, gr,af ) = reading_cnf_with_semantics_and_af(file_path);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 -1.;
    for node in 0..af.nb_argument {
        raw_features.push([
            hcat[node],
            card[node], 
            noselfatt[node],
            maxbased[node],
            gr[node],
            (af.af_attackee[node].len() as f64 / n),
            (af.af_attacker[node].len() as f64 / n),
            if af.af_attacker[node].contains(&node) { 0. } else { 0.5},
        ]);
    }
    Ok(raw_features)
}
#[pyfunction]
fn compute_features_extend_maxgs(file_path : &str)-> PyResult<Vec<[f64;9]>> {
    let (hcat, card, noselfatt, maxbased, gr,af ) = reading_cnf_with_semantics_and_af(file_path);
    let mut raw_features = Vec::with_capacity(af.nb_argument);
    let n = af.nb_argument as f64 -1.;

    for node in 0..af.nb_argument {
        let mut maxh =0.;
        for attacker in af.af_attacker[node].iter() {
            if hcat[*attacker] > maxh {
                maxh = hcat[*attacker];
            }
        };
        raw_features.push([
            hcat[node],
            card[node], 
            noselfatt[node],
            maxbased[node],
            gr[node],
            maxh,
            (af.af_attackee[node].len() as f64 / n),
            (af.af_attacker[node].len() as f64 / n),
            if af.af_attacker[node].contains(&node) { 0. } else { 0.5},
        ]);
    }
    Ok(raw_features)
}
#[pyfunction]
fn compute_features_wo_gs(file_path : &str, iter:usize, tol : f64)-> PyResult<Vec<[f64;6]>> {
    //let start1 = Instant::now();
    let af = reading_file_af(file_path);
    let mut edges = Vec::with_capacity(af.nb_argument*2);
    let mut att1 = Vec::with_capacity(af.nb_argument*2);
    let mut att2 = Vec::with_capacity(af.nb_argument*2);
    for (source, atts) in af.af_attackee.iter().enumerate() {
        for target in atts {
            edges.push((source as u32, *target as u32));
            att1.push(source);
            att2.push(*target);
        }
    }

    //let start = Instant::now();
    let mut g: petgraph::prelude::Graph<u32, ()> = petgraph::graph::DiGraph::<u32, ()>::new();
    g.reserve_exact_nodes(af.nb_argument);
    for i in 0..af.nb_argument as u32 {
        g.add_node(i);
    }
    g.extend_with_edges(&edges);
    //let edge_usize:Vec<(usize,usize)> = edge.iter().map(|x| (x.0 as usize, x.1 as usize)).collect();
    //let graph: DirectedCsrGraph<usize> = GraphBuilder::new().edges(edge_usize).build();
    //println!("GRPAH build {} ms", start.elapsed().as_millis());
    /*let start = Instant::now();
    let (ranks, _iterations, _) = page_rank(&graph, PageRankConfig::new(100, 1E-4, 0.85));
    //println!("PAGE1 : {} ms", start.elapsed().as_millis());*/
    //let start = Instant::now();
    let page_rank = compute_pagerank(&edges, g.node_count(), 0.000001);
    //println!("PAGE2 : {} ms", start.elapsed().as_millis());
    //let start_eig = Instant::now();
    let eig = eigenvector_centrality(&g,  |_| {Ok::<f64,f64>(1.)}, Some(iter), Some(tol)).unwrap().unwrap();
    //println!("EIG T : {} ms", start_eig.elapsed().as_millis());
    //let start = Instant::now();
    let coloring = greedy_node_color(&g);
    //println!("color : {} ms", start.elapsed().as_millis());
    let mut raw_features = Vec::with_capacity(g.node_count());
    //println!("{}", g.node_count());
    //println!("{}", af.nb_argument);
    let n = g.node_count() as f64 -1.;
    for node in 0..g.node_count() {
        raw_features.push([
            coloring[node] as f64, page_rank.get_score(node as u32).unwrap() as f64,
            (af.af_attackee[node].len() + af.af_attackee[node].len() ) as f64 /n, eig[node],
            af.af_attackee[node].len() as f64, af.af_attacker[node].len() as f64    
        ]);
    }
    //println!("Inside Rust {} ms", start1.elapsed().as_millis());
    
    Ok(raw_features)
}

#[pyfunction]
fn reading_cnf_for_dgl( file_path : &str) -> PyResult<(Vec<u32>, Vec<u32>, u32)> {
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file {}");
    let mut content_iter = contents.trim().split('\n');
    let first_line = content_iter.next().unwrap();
    let iter: Vec<&str> = first_line.split_ascii_whitespace().collect();
    let nb_arg = iter[2].parse::<u32>().unwrap();
    let mut att_edge = Vec::with_capacity(contents.capacity());
    let mut target_edge = Vec::with_capacity(contents.capacity());
    for line in content_iter {
        if !line.starts_with('#') {
            let (attacker,target) = parse_cnfattack_line_usigned(line);
            att_edge.push(attacker-1);
            target_edge.push(target-1);
        }
    }
    Ok((att_edge, target_edge, nb_arg))
}

#[pyfunction]
fn reading_cnf_for_dgl_with_semantics( file_path : &str) -> PyResult<(Vec<usize>, Vec<usize>, usize, Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>)> {
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file {}");
    let mut content_iter = contents.trim().split('\n');
    let first_line = content_iter.next().unwrap();
    let iter: Vec<&str> = first_line.split_ascii_whitespace().collect();
    let nb_arg = iter[2].parse::<usize>().unwrap();
    let mut af = ArgumentationFramework::new(nb_arg);
    let mut att_edge = Vec::with_capacity(contents.capacity());
    let mut target_edge = Vec::with_capacity(contents.capacity());
    for line in content_iter {
        if !line.starts_with('#') {
            let (attacker,target) = parse_cnfattack_line_usize(line);
            att_edge.push(attacker-1);
            target_edge.push(target-1);
            af.add_attack(attacker, target);
        }
    }
    let solve_hcat = categorizer::solve(&af);
    let solve_card = card_based::solve(&af);
    let solve_noselfatt = no_self_att_hcat::solve(&af);
    let solve_maxbased = max_based::solve(&af);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    
    Ok((att_edge, target_edge, nb_arg, solve_hcat, solve_card, solve_noselfatt, solve_maxbased, gr))
}
fn reading_apx_af (file_path : &str) -> ArgumentationFramework {
    let mut index = 0;
    let mut index_map: HashMap<_, usize, BuildHasherDefault<AHasher>> = HashMap::default();
    //let mut index_map = HashMap::new();
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n');
    let mut first = true;
    let mut af = ArgumentationFramework::new(1);
    for line in a {
        if line.starts_with("arg") {
                let r = &line[4..line.len()-2];
                index_map.insert(r, index);
                index+=1;
        }
        else if line.starts_with("att") {
            if first {
                first = false;
                af = ArgumentationFramework::new(index_map.len());
            }
            let r = &line[4..line.len()-2];
            let mut s = r.split(',');
            let attacker = *index_map.get(s.next().unwrap()).unwrap();
            let target = *index_map.get(s.next().unwrap()).unwrap();
            af.add_attack_wo_sub(attacker, target);
        }
    }
    af
}
fn reading_apx_af_arg_id (file_path : &str, arg_id: &str) -> (ArgumentationFramework, usize, usize) {
    let mut index = 0;
    let mut tot_edges = 0;
    let mut index_map: HashMap<_, usize, BuildHasherDefault<AHasher>> = HashMap::default();
    //let mut index_map = HashMap::new();
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n');
    let mut first = true;
    let mut af = ArgumentationFramework::new(1);
    for line in a {
        if line.starts_with("arg") {
                let r = &line[4..line.len()-2];
                index_map.insert(r, index);
                index+=1;
        }
        else if line.starts_with("att") {
            if first {
                first = false;
                af = ArgumentationFramework::new(index_map.len());
            }
            let r = &line[4..line.len()-2];
            let mut s = r.split(',');
            let attacker = *index_map.get(s.next().unwrap()).unwrap();
            let target = *index_map.get(s.next().unwrap()).unwrap();
            af.add_attack_wo_sub(attacker, target);
            tot_edges+=1;
        }
    }
    (af, *index_map.get(arg_id).unwrap(), tot_edges)
}
fn _reading_cnf_af (file_path : &str) -> ArgumentationFramework {
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file {}");
    let mut content_iter = contents.trim().split('\n');
    let first_line = content_iter.next().unwrap();
    let iter: Vec<&str> = first_line.split_ascii_whitespace().collect();
    let nb_arg = iter[2].parse::<i32>().unwrap();
    let mut af = ArgumentationFramework::new(nb_arg as usize);
    let mut att_edge = Vec::with_capacity(contents.capacity());
    let mut target_edge = Vec::with_capacity(contents.capacity());
    for line in content_iter {
        if !line.starts_with('#') {
            let (attacker,target) = parse_cnfattack_line_usize(line);
            att_edge.push(attacker-1);
            target_edge.push(target-1);
            af.add_attack(attacker, target);
        }
    }
    af
}
fn reading_cnf_af_tot_edge (file_path : &str) -> (ArgumentationFramework, usize) {
    let mut tot_edges = 0;
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file {}");
    let mut content_iter = contents.trim().split('\n');
    let first_line = content_iter.next().unwrap();
    let iter: Vec<&str> = first_line.split_ascii_whitespace().collect();
    let nb_arg = iter[2].parse::<i32>().unwrap();
    let mut af = ArgumentationFramework::new(nb_arg as usize);
    let mut att_edge = Vec::with_capacity(contents.capacity());
    let mut target_edge = Vec::with_capacity(contents.capacity());
    for line in content_iter {
        if !line.starts_with('#') {
            let (attacker,target) = parse_cnfattack_line_usize(line);
            att_edge.push(attacker-1);
            target_edge.push(target-1);
            af.add_attack(attacker, target);
            tot_edges += 1;
        }
    }
    (af ,tot_edges)
}
fn reading_file_af (file_path : &str) -> ArgumentationFramework {
    let fl = get_first_line(file_path);
    let first_line = fl.trim();
    if first_line.starts_with("p af") {
        let res = reading_cnf_af_tot_edge(file_path);
        return res.0;
    }
    else if first_line.starts_with("arg(") {
        return reading_apx_af(file_path);
    }
    else {
        return reading_tgf_af(file_path);
    }
}
fn reading_file_af_arg(file_path : &str, arg_id: &str) -> (ArgumentationFramework, usize, usize) {
    let fl = get_first_line(file_path);
    let first_line = fl.trim();
    if first_line.starts_with("p af") {
        let res = reading_cnf_af_tot_edge(file_path);
        return (res.0, arg_id.parse::<usize>().unwrap()-1, res.1);
    }
    else if first_line.starts_with("arg(") {
        return reading_apx_af_arg_id(file_path, arg_id);
    }
    else {
        return reading_tgf_af_arg_id(file_path, arg_id);
    }
}

fn _reading_cnf_with_semantics( file_path : &str) -> (Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>) {
    let af = reading_file_af(file_path);
    let solve_hcat = categorizer::solve(&af);
    let solve_card = card_based::solve(&af);
    let solve_noselfatt = no_self_att_hcat::solve(&af);
    let solve_maxbased = max_based::solve(&af);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    (solve_hcat, solve_card, solve_noselfatt, solve_maxbased, gr)
}
fn reading_cnf_with_semantics_and_af( file_path : &str) -> (Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>, ArgumentationFramework) {
    let af = reading_file_af(file_path);
    let solve_hcat = categorizer::solve(&af);
    let solve_card = card_based::solve(&af);
    let solve_noselfatt = no_self_att_hcat::solve(&af);
    let solve_maxbased = max_based::solve(&af);
    //let solve_counting = counting::solve(&af, 2, 0.9);
    let gr = simple_grounded_semantics_solver2::solve(&af);
    (solve_hcat, solve_card, solve_noselfatt, solve_maxbased, gr, af)
}
#[pyfunction]
pub fn reading_apx( file_path : &str) -> PyResult<(Vec<i32>, Vec<(i32,i32)>)> {
    let mut index = 0;
    let mut index_map: HashMap<_, i32, BuildHasherDefault<AHasher>> = HashMap::default();
    
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n').into_iter();
    let mut att = Vec::with_capacity(a.count());
    let a = contents.split('\n');
    for line in a {
        if line.starts_with("arg") {
                /*let buff = line.strip_prefix("arg(").unwrap();
                let buff2 = buff.strip_suffix(").").unwrap();*/
                let r = &line[4..line.len()-2];
                index_map.insert(r, index);
                index+=1;
        }
        else if line.starts_with("att") {
            /*let buff = line.strip_prefix("att(").unwrap();
            let buff2 = buff.strip_suffix(").").unwrap();*/
            let r = &line[4..line.len()-2];
            let mut s = r.split(',');
            let attacker = *index_map.get(s.next().unwrap()).unwrap();
            let target = *index_map.get(s.next().unwrap()).unwrap();
            att.push((attacker, target));
        }
    }
    let mut args = Vec::with_capacity(index as usize);
    for i in 0..index {
        args.push(i as i32);
    }
    Ok((args, att))
}
pub fn reading_apx_for_rustworkx( file_path : &str) -> Vec<(u32,u32)> {
    let mut index = 0;
    let mut index_map: HashMap<_, u32, BuildHasherDefault<AHasher>> = HashMap::default();
    
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n').into_iter();
    let mut att = Vec::with_capacity(a.count());
    let a = contents.split('\n');
    for line in a {
        if line.starts_with("arg") {
                let r = &line[4..line.len()-2];
                index_map.insert(r, index);
                index+=1;
        }
        else if line.starts_with("att") {
            let r = &line[4..line.len()-2];
            let mut s = r.split(',');
            let attacker = *index_map.get(s.next().unwrap()).unwrap();
            let target = *index_map.get(s.next().unwrap()).unwrap();
            att.push((attacker, target));
        }
    }
    att
}
pub fn reading_apx_for_dgl( file_path : &str) -> (Vec<u32>,Vec<u32>, u32) {
    let mut index = 0;
    let mut index_map: HashMap<_, u32, BuildHasherDefault<AHasher>> = HashMap::default();
    
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
    let a = contents.split('\n').into_iter();
    let ca = a.count();
    let mut source = Vec::with_capacity(ca);
    let mut targetv = Vec::with_capacity(ca);
    let a = contents.split('\n');
    for line in a {
        if line.starts_with("arg") {
                let r = &line[4..line.len()-2];
                index_map.insert(r, index);
                index+=1;
        }
        else if line.starts_with("att") {
            let r = &line[4..line.len()-2];
            let mut s = r.split(',');
            let attacker = *index_map.get(s.next().unwrap()).unwrap();
            let target = *index_map.get(s.next().unwrap()).unwrap();
            source.push(attacker);
            targetv.push(target);
        }
    }
    (source, targetv, index_map.len() as u32)
}
fn parse_cnfattack_line (line : &str) -> (i32,i32) {
    let mut a = line.split_ascii_whitespace();
    let att = a.next().unwrap().parse::<i32>().unwrap();
    let targ = a.next().unwrap().parse::<i32>().unwrap();
    (att,targ)
}
fn parse_cnfattack_line_usigned (line : &str) -> (u32,u32) {
    let mut a = line.split_ascii_whitespace();
    let att = a.next().unwrap().parse::<u32>().unwrap();
    let targ = a.next().unwrap().parse::<u32>().unwrap();
    (att,targ)
}
fn parse_cnfattack_line_usize (line : &str) -> (usize,usize) {
    let mut a = line.split_ascii_whitespace();
    let att = a.next().unwrap().parse::<usize>().unwrap();
    let targ = a.next().unwrap().parse::<usize>().unwrap();
    (att,targ)
}

/// A Python module implemented in Rust.
#[pymodule]
fn af_reader_py(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(reading_apx, m)?)?;
    m.add_function(wrap_pyfunction!(reading_cnf, m)?)?;
    m.add_function(wrap_pyfunction!(reading_cnf_for_dgl, m)?)?;
    m.add_function(wrap_pyfunction!(reading_file_for_dgl, m)?)?;
    m.add_function(wrap_pyfunction!(reading_cnf_for_dgl_with_semantics, m)?)?;
    m.add_function(wrap_pyfunction!(compute_eigenvector_centrality, m)?)?;
    m.add_function(wrap_pyfunction!(compute_features, m)?)?;
    m.add_function(wrap_pyfunction!(compute_features_extend, m)?)?;
    m.add_function(wrap_pyfunction!(compute_features_extend_maxgs, m)?)?;
    m.add_function(wrap_pyfunction!(compute_features_wo_gs, m)?)?;
    m.add_function(wrap_pyfunction!(compute_only_gs, m)?)?;
    m.add_function(wrap_pyfunction!(compute_only_gs_w_gr, m)?)?;
    m.add_function(wrap_pyfunction!(compute_only_gs_w_gr_sa_ed, m)?)?;
    m.add_function(wrap_pyfunction!(compute_only_gs_w_gr_sa_ed_eb, m)?)?;
    m.add_function(wrap_pyfunction!(compute_only_gs_w_gr_sa_ed_perso, m)?)?;
    m.add_function(wrap_pyfunction!(compute_only_gs_w_gr_sa_ed_fuzz, m)?)?;
    m.add_function(wrap_pyfunction!(compute_only_gs_w_gr_sa_ed_perso_mod, m)?)?;
    m.add_function(wrap_pyfunction!(special, m)?)?;
    m.add_function(wrap_pyfunction!(special_only, m)?)?;
    m.add_function(wrap_pyfunction!(special_wo_gs, m)?)?;
    m.add_function(wrap_pyfunction!(special_gs, m)?)?;
    m.add_function(wrap_pyfunction!(special_gs_for_gat, m)?)?;
    m.add_function(wrap_pyfunction!(read_lars_solution_dc, m)?)?;
    m.add_function(wrap_pyfunction!(read_lars_solution_ds, m)?)?;
    Ok(())
}
