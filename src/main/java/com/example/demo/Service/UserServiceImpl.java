	package com.example.demo.Service;
	
	import org.springframework.beans.factory.annotation.Autowired;
	import org.springframework.security.core.userdetails.UserDetails;
	import org.springframework.security.core.userdetails.UserDetailsService;
	import org.springframework.security.core.userdetails.UsernameNotFoundException;
	import org.springframework.stereotype.Service;
	import com.example.demo.Repository.UserRepository;
	
	@Service
	public class UserServiceImpl implements UserDetailsService {
	
		@Autowired
		UserRepository userRepository;
	
		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			return this.userRepository.findByEmail(username)
					.orElseThrow(() -> new UsernameNotFoundException("User Not Found !!!"));
		}
	}
