package com.example.demo.Service;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.demo.Dto.JwtAuthenticationResponse;
import com.example.demo.Dto.RefreshTokenRequest;
import com.example.demo.Dto.SignInRequest;
import com.example.demo.Dto.SignUpRequest;
import com.example.demo.Entity.User;
import com.example.demo.Repository.UserRepository;
import com.example.demo.Utils.Role;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl {

	@Autowired
	UserRepository userRepository;
	@Autowired
	PasswordEncoder passwordEncoder;
	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	JWTServiceImpl jwtService;

	public User signUp(SignUpRequest signUpRequest) {
		User user = new User();
		user.setEmail(signUpRequest.getEmail());
		user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
		user.setRole(Role.USER);
		return userRepository.save(user);
	}

	public JwtAuthenticationResponse signIn(SignInRequest signInRequest) {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(signInRequest.getEmail(), signInRequest.getPassword()));
		} catch (BadCredentialsException e) {
			throw new IllegalArgumentException("Incorrect email or password");
		}

		User user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(
				() -> new UsernameNotFoundException("User not found with email: " + signInRequest.getEmail()));

		String jwt = jwtService.generateToken(user);
		String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

		JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
		jwtAuthenticationResponse.setToken(jwt);
		jwtAuthenticationResponse.setRefreshToken(refreshToken);

		return jwtAuthenticationResponse;
	}

	public User adminSignUp(SignUpRequest signUpRequest) {
		User user = new User();
		user.setEmail(signUpRequest.getEmail());
		user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
		user.setRole(Role.ADMIN);
		return userRepository.save(user);
	}

	public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
		String userEmail = jwtService.extractUserName(refreshTokenRequest.getToken());
		User user = userRepository.findByEmail(userEmail).orElseThrow();
		if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)) {
			var jwt = jwtService.generateToken(user);

			JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
			jwtAuthenticationResponse.setToken(jwt);
			jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());

			return jwtAuthenticationResponse;
		}
		return null;
	}
}
