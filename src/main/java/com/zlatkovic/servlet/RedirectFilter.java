/*
 * com.zlatkovic.servlet.RedirectFilter
 * @(#)RedirectFilter.java 2.0 15.10.2007
 *
 * (c) 2004-2007 Igor Zlatkovic. All rights reserved.
 * The use of this software is subject to licence terms.
 * See http://www.zlatkovic.com/licence.en.html.
 */

package com.zlatkovic.servlet;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * A simple, configurable URI redirector. It can rewrite a request URI and then 
 * either forward it for processing locally, or send a HTTP redirect to the client.
 * 
 * @see javax.servlet.Filter
 * 
 * @author igor
 * @version 2.0
 */
public class RedirectFilter implements Filter {
	
	/*
	 * A name by which this filter is identified in logs.
	 */
	protected String filterName;
	
	/* 
	 * A full path to the configuration file, the flag indicating whether we
	 * should allow rereading it dynamically at runtime and a flag indicating
	 * whether we should log the redirects as they happen. 
	 */
	protected String configFileName = null;
	protected boolean reloadConfig = false;
	protected boolean logRedirects = false;
	protected boolean contextAware = false;
	
	/*
	 * FilterConfig object we shall need for logging. 
	 */
	protected FilterConfig filterConfig;
	
	/*
	 * A collection of redirect rules.
	 */
	protected List<RedirectRule> redirectRules;
	
	/*
	 * Defines the forward action. It just derives from RedirectRule, giving
	 * itself an unique type by which it can be recognised later. It does not
	 * add any additional fields, as they are not needed.
	 */
	protected class ForwardAction extends RedirectRule {
	}

	/*
	 * Defines the redirect action. It inherits the basic fields from RedirectRule
	 * and adds few of its own.
	 */
	protected class RedirectAction extends RedirectRule {
		public boolean permanent = false;
		public boolean encodeUrl = false;
		public boolean entireUrl = false;
		public String cache;

	}
	
	/*
	 * Defines a action which is to stop processing the current request.
	 * This is in the wrong place in the class hierarchy as it doesn't have a target.
	 */
	protected class IgnoreAction extends RedirectRule {
		
	}

	/*
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig config) 
			throws ServletException {
		
		filterName = getClass().getName();
		filterName = filterName.substring(filterName.lastIndexOf('.') + 1);

		filterConfig = config;
		
		configFileName = config.getInitParameter("configFile");
		configFileName = config.getServletContext().getRealPath(configFileName);

		reloadConfig = Boolean.valueOf(
				config.getInitParameter("reloadConfig")).booleanValue();
		logRedirects = Boolean.valueOf(
				config.getInitParameter("logRedirects")).booleanValue();
		contextAware = Boolean.valueOf(
				config.getInitParameter("contextAware")).booleanValue();

		loadConfiguration();
	}

	/* 
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {
		// Should I do something here?
	}

	/*
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, 
	 * 	javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		
		if (processCommand(httpRequest, httpResponse) == true)
			return;

		if (redirectRules == null || redirectRules.size() == 0) {
			chain.doFilter(request, response);
			return;
		}

		String ctxPath = httpRequest.getContextPath();
		
		// Use a local reference to the redirect rules vector, so we can finish
		// our job with it, even if another thread interrupts us, reloads the 
		// configuration and thus puts a new vector in the redirectRules field.
		List<RedirectRule> rules = redirectRules;

		for (int i = 0; i < rules.size(); i++) {
			RedirectRule rule = (RedirectRule) rules.get(i);
			
			String matchMe = getRequestURI(httpRequest);
			if (rule instanceof RedirectAction) {
				if (((RedirectAction)rule).entireUrl == true && 
						httpRequest.getMethod().equalsIgnoreCase("GET")) {
					matchMe = httpRequest.getRequestURL().toString();
					String qry = httpRequest.getQueryString();
					if (qry != null && qry.length() != 0)
						matchMe += "?" + qry;
				}
			}

			Matcher matcher = rule.match.matcher(matchMe);
			
			boolean matches = false;
			if (matcher.matches()) {
				boolean localOk = rule.localAddress == null || 
					rule.localAddress.equals(httpRequest.getLocalAddr());
				boolean remoteOk = rule.remoteRange == null || 
					isAddressInRange(rule.remoteRange, httpRequest.getRemoteAddr());
				if (localOk && remoteOk)
					matches = true;
			}

			if (matches == true) {
				String target = rule.target;
				
				if (rule instanceof IgnoreAction) {
					// Stop looking at rules.
					break;
				}

				if (matcher.groupCount() > 0) {
					for (int j = 1; j <= matcher.groupCount(); j++)
						target = target.replaceAll(
								"\\$" + String.valueOf(j), matcher.group(j));
				}
				
				if (contextAware == true && target.indexOf("://") == -1 &&
						!(rule instanceof ForwardAction)) {
					if (target.startsWith("/") == false && ctxPath.equals("/") == false)
						target = "/" + target;
					target = ctxPath + target;
				}

				if (processRule(httpRequest, httpResponse, rule, target) == true) {
					return;
				} else {
					filterConfig.getServletContext().log(filterName + ": Unknown rule.");
				}
			}
		}

		chain.doFilter(request, response);
	}

	/**
	 * Reads the configuration file and sets up the filter rules. 
	 */
	protected synchronized void loadConfiguration() throws ServletException {

		if (configFileName == null) {
			// Missing init parameter? That's okay, perhaps there is nothing to
			// redirect. 
			return;
		}
		
		File configFile = new File(configFileName);
		DocumentBuilderFactory docBuildFac = DocumentBuilderFactory.newInstance();
		
		DocumentBuilder docBuild;
		try {
			if (docBuildFac.isValidating())
				docBuildFac.setValidating(false);
			docBuild = docBuildFac.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			// Problems with the XML parser? Very unlikely, the container wouldn't 
			// work at all. Whatever it is, it is serious, we give up.
			throw new ServletException(e.getMessage());
		}

		Document doc;
		try {
			doc = docBuild.parse(configFile);
		} catch (IOException e) {
			// File configFile not found, or similar.
			throw new ServletException(e.getMessage());
		} catch (SAXException e) {
			// Invalid XML in configFile, or similar.
			throw new ServletException(e.getMessage());
		}
		
		redirectRules = new Vector<RedirectRule>();
		
		Node node = doc.getDocumentElement();
		while (node != null) {
			if (node.getNodeType() == Node.ELEMENT_NODE)  {
				RedirectRule rule = loadRule((Element) node);
				if (rule != null)
					redirectRules.add(rule);
			}
			if (node.hasChildNodes() == true)
				node = node.getFirstChild();
			else if (node.getNextSibling() != null)
				node = node.getNextSibling();
			else if (node.getParentNode() != null)
				node = node.getParentNode().getNextSibling();
			else
				node = null;
		}
				
		filterConfig.getServletContext().log(filterName + ": Loaded " +
				redirectRules.size() + " rule(s).");
	}
	
	/**
	 * Creates a redirect rule object from the element node which should have
	 * turned up in the configuration file.
	 * 
	 * It does full checking of the inspected element to see if the required
	 * XML grammar is okay. In a perfect world this would not be necessary, I 
	 * would turn on XML validation and a file with bad grammar would be 
	 * rejected up-front for not matching the schema or DTD. But as things are,
	 * people are not always setting up a local catalog for frequently used
	 * files. This then means that every restart of every server worldwide
	 * which uses this software would trigger a HTTP request to my server in
	 * order to fetch the DTD for validation, thus generating traffic I at the
	 * end must pay for. To avoid that, XML validation is turned off and the 
	 * bad grammar we gracefully ignore here. As the result, the user is not
	 * notified about problems, the filter simply won't work if there are any, 
	 * but there is nothing I can do about that right now.
	 * 
	 * @param elem: A rule element from the configuration file.
	 * 
	 * @return a new redirect rule object or null if the element cannot
	 * 	be recognised.
	 */
	protected RedirectRule loadRule(Element elem) {
		
		// Ignore if required attributes are missing
		if (!elem.hasAttribute("match"))
			return null;
		
		String action = elem.getTagName();
		
		if (action.equals("forward")) {
			ForwardAction rule = new ForwardAction();
			if (!elem.hasAttribute("target")) {
				return null;
			}
			rule.match = Pattern.compile(elem.getAttribute("match"));
			rule.target = elem.getAttribute("target");
			
			rule.localAddress = elem.hasAttribute("local-address")? 
					elem.getAttribute("local-address") : null;
			rule.remoteRange = elem.hasAttribute("remote-address")?
					elem.getAttribute("remote-address") : null;
			
			return rule;
		}
				
		if (action.equals("redirect")) {
			RedirectAction rule = new RedirectAction();
			if (!elem.hasAttribute("target")) {
				return null;
			}
			rule.match = Pattern.compile(elem.getAttribute("match"));
			rule.target = elem.getAttribute("target");
			
			rule.localAddress = elem.hasAttribute("local-address")? 
					elem.getAttribute("local-address") : null;
			rule.remoteRange = elem.hasAttribute("remote-address")?
					elem.getAttribute("remote-address") : null;
			
			rule.permanent = elem.hasAttribute("permanent")?
					elem.getAttribute("permanent").equals("yes") : false;
			rule.encodeUrl = elem.hasAttribute("encode-url")? 
					elem.getAttribute("encode-url").equals("yes") : false;
			rule.entireUrl = elem.hasAttribute("entire-url")?
					elem.getAttribute("entire-url").equals("yes") : false;
			rule.cache = elem.hasAttribute("cache")?
					elem.getAttribute("cache") : null;

			return rule;
		}
		
		if (action.equals("ignore")) {
			IgnoreAction rule = new IgnoreAction();
			
			rule.match = Pattern.compile(elem.getAttribute("match"));
			
			rule.localAddress = elem.hasAttribute("local-address")? 
					elem.getAttribute("local-address") : null;
			rule.remoteRange = elem.hasAttribute("remote-address")?
					elem.getAttribute("remote-address") : null;
			return rule;
		}
		return null;
	}

	/**
	 * Processes the filter command if one is specified in the request URI. For example, 
	 * a command can be an instruction to reload filter rules. If this method returns
	 * true, the request should be considered handled.
	 * 
	 * @param request: HttpServletRequest object for this request.
	 * @param response: HttpServletResponse object for this request.
	 * @param uri: Preprocessed request URI
	 * 
	 * @return true if the request URI specifies a command, false otherwise. If a command
	 * 	is specified and its execution fails, an exception will be thrown.
	 * 
	 * @throws ServletException
	 * @throws IOException
	 */
	protected boolean processCommand(HttpServletRequest request, HttpServletResponse response) 
			throws ServletException, IOException {

		String uri = getRequestURI(request);
		
		if (uri.endsWith("/redirect-filter")) {
			String cmd = request.getParameter("c");
			if (cmd != null && cmd.equals("reload") && reloadConfig == true) {
				loadConfiguration();
				response.setContentType("text/plain");
				response.getWriter().println(filterName + ": Loaded " + 
						redirectRules.size() + " rule(s).");
				return true;
			}
		}
		
		return false;
	}

	/**
	 * Processes a single redirection rule that matched the request URI. 
	 * If this method returns true, the request should be considered handled.
	 * 
	 * @param request: HttpServletRequest object for this request.
	 * @param response: HttpServletResponse object for this request.
	 * @param rule: The rule that matched the request URI.
	 * @param targetURL: The preprocessed target URL.
	 * 
	 * @return true if the rule action has been recognised, false otherwise. If the rule action
	 * 	has been recognised but the handling fails, an exception will be thrown.
	 * 
	 * @throws ServletException
	 * @throws IOException
	 */
	protected boolean processRule(HttpServletRequest request, HttpServletResponse response, 
			RedirectRule rule, String targetURL) 
			throws ServletException, IOException {
		
		String finalURL = getFinalURL(request, response, rule, targetURL);
		
		if (rule instanceof RedirectAction) {
			RedirectAction redirectRule = (RedirectAction)rule;
			if (redirectRule.cache != null) {
				response.addHeader("Cache-Control", redirectRule.cache);
			}
			if (redirectRule.permanent == true) {
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.addHeader("Location", finalURL);
			
			} else {
				response.sendRedirect(finalURL);
			}

			if (logRedirects == true) {
				filterConfig.getServletContext().log(filterName + ": " +
						"Redirected '" + getRequestURI(request) + "' to '" + finalURL + "'");
			}

			return true;
		
		} else if (rule instanceof ForwardAction)  {
			RequestDispatcher reqDisp = request.getRequestDispatcher(targetURL);
			reqDisp.forward(request, response);
			
			if (logRedirects == true) {
				filterConfig.getServletContext().log(filterName + ": " +
						"Forwarded '" + getRequestURI(request) + "' to '" + targetURL + "'");
			}
			
			return true;
		}
		
		return false;
	}

	/**
	 * Returns the URI the client used to access the specified resource.
	 * If the filter operates context-aware, the URI will have the context path
	 * stripped off, so the rules can be written in a manner which works no matter
	 * where the filter is deployed.
	 * 
	 * @param request: HttpServletRequest object for this request.
	 * 
	 * @return: The request URI, possibly adapted to support context independence.
	 */
	protected String getRequestURI(HttpServletRequest request) {
		
		String uri = request.getRequestURI();
		String ctxPath = request.getContextPath();

		if (contextAware == true && uri.startsWith(ctxPath))
			uri = uri.substring(ctxPath.length());

		return uri;
	}
	
	/**
	 * Converts a possibly relative URL to absolute URL. If the supplied URL
	 * doesn't need any conversion, it remains unchanged.
	 * 
	 * @param httpRequest: HttpServletRequest object which must be valid for the 
	 * 	duration if the call
	 * @param url: A relative URL which should be converted to absolute URL.
	 * 
	 * @return Absolute URL if converted, or unchanged URL if the conversion 
	 * 	wasn't necessary or possible.
	 */
	protected String getAbsoluteURL(HttpServletRequest httpRequest, String url) {
		
		if (url == null)
			return null;
		if (url.indexOf("://") != -1)			
			return url;

		String scheme = httpRequest.getScheme();
		String serverName = httpRequest.getServerName();
		int port = httpRequest.getServerPort();
		boolean slashLeads = url.startsWith("/");

		String absoluteURL = scheme + "://" + serverName;
		
		if ((scheme.equals("http") && port != 80) || 
				(scheme.equals("https") && port != 443))
			absoluteURL += ":" + port;
		if (!slashLeads)
			absoluteURL += "/";

		absoluteURL += url;
		
		return absoluteURL;
	}
	
	/**
	 * Converts the target URL into a final URL for a particular request and particular
	 * rule that matched. This involves converting a possibly relative URL to absolute
	 * URL and encoding it by the response object.
	 * 
	 * @param request: HttpServletRequest object for this request.
	 * @param response: HttpServletResponse object for this request.
	 * @param rule: The redirect rule that matched this request.
	 * @param targetURL: The target URL.
	 * 
	 * @return the final URL which can be sent back to the client as redirection.
	 */
	protected String getFinalURL(HttpServletRequest request, HttpServletResponse response,
			RedirectRule rule, String targetURL) {

		String finalURL = getAbsoluteURL(request, targetURL);
		if ((rule instanceof RedirectAction) && ((RedirectAction)rule).encodeUrl == true)
			finalURL = response.encodeRedirectURL(finalURL);

		return finalURL;
	}
	
	/**
	 * Figures out whether the specified address resides within the specified
	 * address range.
	 * 
	 * @param range: A range in notation address/netmask, for example
	 * 	127.0.0.1/255.0.0.0
	 * @param address: An address to be tested.
	 * 
	 * @return true if the address is within the range, false otherwise.
	 */
	protected boolean isAddressInRange(String range, String address) 
			throws ServletException {
		
		String network;
		String mask;
		
		int slashPos = range.indexOf('/');
		if (slashPos == -1) {
			network = range;
			mask = "255.255.255.255";
		} else {
			network = range.substring(0, slashPos);
			mask = range.substring(slashPos + 1);
		}
		
		try {
			byte[] netBytes = InetAddress.getByName(network).getAddress();
			byte[] maskBytes = InetAddress.getByName(mask).getAddress();
			byte[] addrBytes = InetAddress.getByName(address).getAddress();
			for (int i = 0; i < netBytes.length; i++) {
				if ((netBytes[i] & maskBytes[i]) != (addrBytes[i] & maskBytes[i]))
					return false;
			}
			
		} catch (UnknownHostException e) {
			// Should never happen, because we work with raw IP addresses, not
			// with host names.
			throw new ServletException(e.getMessage());
		}
		
		return true;
	}
}
