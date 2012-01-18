/*
 * com.zlatkovic.servlet.RedirectFilter
 * @(#)RedirectRule.java 2.0 15.10.2007
 *
 * (c) 2004-2007 Igor Zlatkovic. All rights reserved.
 * The use of this software is subject to licence terms.
 * See http://www.zlatkovic.com/licence.en.html.
 */

package com.zlatkovic.servlet;

/**
 * A redirect rule base class, the parent of all redirect actions. It was
 * an inner class of RedirectFilter before, now it is outsourced in order
 * to allow classes derived from RedirectFilter to inherit from it.
 * 
 * @see javax.servlet.Filter
 * 
 * @author igor
 * @version 2.0
 */
public class RedirectRule {
	public String match;
	public String target;
	public String localAddress;
	public String remoteRange;
}
