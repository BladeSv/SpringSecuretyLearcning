package by.mitrahovich.securety;

import javax.crypto.SecretKey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import by.mitrahovich.auth.ApplicationUserService;
import by.mitrahovich.jwt.JwtConfig;
import by.mitrahovich.jwt.JwtTokenVerifier;
import by.mitrahovich.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecuretyConfig extends WebSecurityConfigurerAdapter {

	private final ApplicationUserService applicationUserService;

	private final PasswordEncoder passwordEncoder;

	private final JwtConfig jwtConfig;

	private final SecretKey secretKey;

	public ApplicationSecuretyConfig(ApplicationUserService applicationUserService, PasswordEncoder passwordEncoder,
			JwtConfig jwtConfig, SecretKey secretKey) {
		this.applicationUserService = applicationUserService;
		this.passwordEncoder = passwordEncoder;
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

//		http//
////				.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//
////				.and()
//				.csrf().disable()//
//				.authorizeHttpRequests().antMatchers("/", "index", "/css/*", "/js/*").permitAll()//
//				.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())//
////				.antMatchers(HttpMethod.DELETE, "/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())//
////				.antMatchers(HttpMethod.POST, "/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())//
////				.antMatchers(HttpMethod.PUT, "/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())//
////				.antMatchers(HttpMethod.GET, "/managment/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//				.anyRequest().authenticated().and()
//				// .httpBasic();//
//				.formLogin().loginPage("/login").permitAll()//
//				.defaultSuccessUrl("/courses", true)//
//				.passwordParameter("password").usernameParameter("username").and()//
//				.rememberMe().tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)).key("somethingverysevure")//
//				.rememberMeParameter("remember-me")//
//				.and()//
//				.logout().logoutUrl("/logout")//
//				.clearAuthentication(true).invalidateHttpSession(true)//
//				.deleteCookies("JSESSIONID", "remember-me")//
//				.logoutSuccessUrl("/login");

		http//
				.csrf().disable()//
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.addFilter(
						new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))//
				.addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey),
						JwtUsernameAndPasswordAuthenticationFilter.class)
				.authorizeHttpRequests().antMatchers("/", "index", "/css/*", "/js/*").permitAll()//
				.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())//
				.anyRequest().authenticated();

	}

//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//
//		UserDetails annaSmithUser = User.builder().username("anna").password(passwordEncoder.encode("pas"))
//				// .roles(STUDENT.name())
//				.authorities(STUDENT.getGrantedAuthority()).build();
//
//		UserDetails admin = User.builder().username("linda").password(passwordEncoder.encode("pas"))
//				// .roles(ADMIN.name())
//				.authorities(ADMIN.getGrantedAuthority()).build();
//
//		UserDetails tom = User.builder().username("tom").password(passwordEncoder.encode("pas"))
//				// .roles(ADMINTRAINEE.name())
//				.authorities(ADMINTRAINEE.getGrantedAuthority()).build();
//
//		return new InMemoryUserDetailsManager(annaSmithUser, admin, tom);
//	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();

		authenticationProvider.setPasswordEncoder(passwordEncoder);
		authenticationProvider.setUserDetailsService(applicationUserService);
		return authenticationProvider;
	}

}
