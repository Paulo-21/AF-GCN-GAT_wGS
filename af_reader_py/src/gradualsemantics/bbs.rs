use crate::graph::ArgumentationFramework;
const EPSILON : f64 = 0.001;

pub fn solve(af : &ArgumentationFramework) -> Vec<f64> {
    let score = compute_final_score(af);
    score
}
fn compute_final_score(af : &ArgumentationFramework) -> Vec<f64> {
    let mut res = vec![1.0;af.nb_argument];
    let mut new_scores = vec![1.0;af.nb_argument];
    //let mut k = 0;
	for _i in 0..100 {
	    for i in 0..res.len() {
		    let mut sum_score_attacker = 1.;
			for  attacker in &af.af_attacker[i] {
				unsafe {
					sum_score_attacker += 1./res.get_unchecked(*attacker);
				}
			}
			new_scores[i] +=  sum_score_attacker;
        }
        /*if stabilisation(&res, &new_scores) {
            return new_scores;
        }*/
        std::mem::swap(&mut res, &mut new_scores);
	}
    res
}
fn stabilisation(tab1 : &[f64], tab2 : &[f64]) -> bool {
	for (i, x) in tab1.iter().enumerate() {
		unsafe {
			if (x-tab2.get_unchecked(i)).abs() > EPSILON {
				return false;
			}
		}
	}
	true
}
