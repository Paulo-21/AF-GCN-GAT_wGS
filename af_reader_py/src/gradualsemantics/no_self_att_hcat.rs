use crate::graph::ArgumentationFramework;

const EPSILON : f64 = 0.0001;

pub fn solve(af : &ArgumentationFramework) -> Vec<f64> {
    let score = compute_final_score(af);
	score
}

fn compute_final_score(af : &ArgumentationFramework) -> Vec<f64> {
    let mut res = init_scores(af);
    let mut new_scores = init_scores(af);
    let mut has_changed = true;
    
		while has_changed {
			has_changed = false;
			for i in 0..res.len() {
				let mut sum_score_attacker = 0.;
				let ic = i;
				for  attacker in &af.af_attacker[i] {
					if ic == *attacker {
						new_scores[i] = 0.;
						break;
					}
					unsafe {
						sum_score_attacker += res.get_unchecked(*attacker);
					}
				}
				if new_scores[i] == 0. { continue; }

				new_scores[i] =  1. / (1. + sum_score_attacker);
				if (new_scores[i] - res[i]).abs() > EPSILON {
					has_changed = true;
				}
			}
            std::mem::swap(&mut res, &mut new_scores);
		}
		res
}

fn init_scores(af : &ArgumentationFramework) -> Vec<f64> {
    vec![1.0;af.nb_argument]
}