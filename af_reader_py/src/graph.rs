pub struct ArgumentationFramework {
    pub af_attacker : Vec<Vec<usize>>,
	pub af_attackee : Vec<Vec<usize>>,
    pub nb_argument : usize
}

impl ArgumentationFramework {
    pub fn new(nb_arg : usize) -> Self {
        let af_attackee = vec![Vec::new();nb_arg];
        let af_attacker = vec![Vec::new();nb_arg];
        Self { af_attackee , af_attacker, nb_argument : nb_arg }
    }
    pub fn add_attack(&mut self, attacker : usize, target : usize) {
        self.af_attacker[target-1].push(attacker-1);
        self.af_attackee[attacker-1].push(target-1);
    }
    pub fn add_attack_wo_sub(&mut self, attacker : usize, target : usize) {
        self.af_attacker[target].push(attacker);
        self.af_attackee[attacker].push(target);
    }
}