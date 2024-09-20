use std::time::Instant;

use crate::graph::ArgumentationFramework;
const EPSILON : f64 = 0.01;

pub fn solve(af : &ArgumentationFramework, gr: &Vec<f64>, hcat:&Vec<f64>) -> Vec<f64> {
    let mut res = vec![0.5;af.nb_argument];
    let mut new_scores = vec![0.5;af.nb_argument];
    let mut iter = 0;
		loop {
			for i in 0..res.len() {
                let start = Instant::now();
				let mut sum_score_attacker = 0.;
				for  attacker in &af.af_attacker[i] {
					if gr[*attacker] == 1. || hcat[*attacker] >= 0.8 {
                        sum_score_attacker = 0.;
                        break;
                    }
                    let mut maxdeff =0.;
                    for deffender in af.af_attacker[*attacker].iter() {
                        let mut a = res[*deffender];
                        if hcat[*deffender] > 0.8  { a = hcat[*deffender] };
                        if gr[*deffender] == 1. { a = 1.; }
                        if a > maxdeff {
                            maxdeff = a;
                        }
                    }
                    sum_score_attacker += maxdeff;
				}
                if af.af_attacker[i].len() > 0 {
                    new_scores[i] = sum_score_attacker/af.af_attacker[i].len() as f64;
                }
                else {
                    new_scores[i] = 1.;
                }
                println!("{} elapsed", start.elapsed().as_millis());
			}
            std::mem::swap(&mut res, &mut new_scores);
            if stabilisation(&res, &new_scores) {
                return res;
            }
            iter+=1;
            println!("{}", iter);
		}
		
}
fn stabilisation(tab1 : &[f64], tab2 : &[f64]) -> bool {
	for (i, x) in tab1.iter().enumerate() {
		if (x-tab2[i]).abs() > EPSILON {
			return false;
		}
	}
	true
}