use crate::graph::ArgumentationFramework;

pub fn solve(af : &ArgumentationFramework) -> Vec<f64> {

    let mut label_in_final = init_labelling2(af);
    let mut label_in_new = label_in_final.clone();
    let mut label_out = vec![false;af.nb_argument];
    let mut suspect_in = Vec::with_capacity(af.nb_argument);
    let mut has_changed = true;
    let mut n_label_in_new = Vec::with_capacity(af.nb_argument/10);
    while has_changed {
        has_changed = false;

        for i in &label_in_new {
            for argument in &af.af_attackee[*i] {
                if !label_out[*argument as usize] {
                    label_out[*argument as usize] = true;
                    suspect_in.push(&af.af_attackee[*argument as usize]);
                }
            }
        }
        for el in &suspect_in {
            for index_of_suspect in &**el {
                if !label_out[*index_of_suspect as usize] && all_attackers_are_out(af, &label_out, *index_of_suspect as usize)  {
                    n_label_in_new.push(*index_of_suspect as usize);
                    label_in_final.push(*index_of_suspect as usize);
                    has_changed = true;
                    
                }
            }
        }
        suspect_in.clear();
        label_in_new.clear();
        std::mem::swap(&mut label_in_new, &mut n_label_in_new);
    }
    
    let mut r = vec![0.5; af.nb_argument];
    for l in label_in_final {
        r[l] = 1.;
        for k in &af.af_attackee[l] {
            r[*k as usize] = 0.;
        }
    }
    r
}

fn init_labelling2(af : &ArgumentationFramework) -> Vec<usize> {
    let mut label_in : Vec<usize> = Vec::with_capacity(af.nb_argument);
    
    for i in 0..af.nb_argument {
	    if af.af_attacker[i].is_empty() {
			label_in.push(i);
		}
	}
    label_in
}
fn all_attackers_are_out(af : &ArgumentationFramework, labelling : &[bool], index : usize) -> bool {
    for attacker in &af.af_attacker[index] {
		if !labelling[(*attacker) as usize] {
			return false;
		}
	}
	true
}