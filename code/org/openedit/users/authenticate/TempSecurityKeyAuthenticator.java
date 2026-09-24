package org.openedit.users.authenticate;

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openedit.Data;
import org.openedit.ModuleManager;
import org.openedit.data.Searcher;
import org.openedit.data.SearcherManager;
import org.openedit.hittracker.HitTracker;
import org.openedit.users.User;
import org.openedit.users.UserManager;
import org.openedit.users.UserManagerException;

public class TempSecurityKeyAuthenticator extends BaseAuthenticator
{
	private static final Log log = LogFactory.getLog(TempSecurityKeyAuthenticator.class);

	ModuleManager fieldModuleManager;
	
	public ModuleManager getModuleManager()
	{
		return fieldModuleManager;
	}

	public void setModuleManager(ModuleManager inModuleManager)
	{
		fieldModuleManager = inModuleManager;
	}

	public boolean authenticate(AuthenticationRequest inAReq) throws UserManagerException
	{
		User user = inAReq.getUser();
		String code = inAReq.get("templogincode");
		
		if( code == null)
		{
			return false;
		}
		//Search for the code
		UserManager userManager = getUserManager(inAReq.getCatalogId());
		
		Searcher searcher = getSearcherManager().getSearcher("system", "templogincode");
		
		Calendar cal  = Calendar.getInstance();
		cal.add(Calendar.HOUR, -1); //24 hours
		Date newerthan = cal.getTime();
		// Match code and user in Java, only the date in Elasticsearch: exact() follows the field XML (analyzed ->
		// "securitycode.exact"), but each index keeps the mapping it was created with and the XML has flipped between
		// analyzed and not_analyzed, so a mismatch found no code. Only the last hour's codes are scanned.
		Data found = null;
		for (Object hit : searcher.query().after("date",newerthan).search())
		{
			Data row = (Data) hit;
			if (code.equals(row.get("securitycode")) && user.getId().equals(row.get("user")))
			{
				found = row;
				break;
			}
		}

		if( found == null)
		{
			if( "testautologinuser".equals(user.getId()))
			{
				if( "666666".equals( code ) ) 
				{
					if( user.isEnabled())
					{
						return true;
					}
				}
			}
			else
			{
				log.error("Security code expired or missing " + code);
				throw new UserManagerException("Security code expired or missing");
			}
		}

		
		if( found != null)
		{
			String securitycode = found.get("securitycode");  //Double checking
			if( code.equals(securitycode))
			{
				HitTracker codes = searcher.query().match("email",found.get("email")).search();
				searcher.deleteAll(codes, user);
				// match("email") finds nothing when the field XML and the index mapping disagree; still burn this code
				searcher.delete(found, user);
				return true;
			}
		
			
		}
		
		
		
		return false;
	}

	protected SearcherManager getSearcherManager()
	{
		return (SearcherManager)getModuleManager().getBean("searcherManager");
	}

	private UserManager getUserManager(String inCatalogId)
	{
		if(inCatalogId != null) {
			return  (UserManager) getModuleManager().getBean( inCatalogId, "userManager");

		} else {
			return  (UserManager) getModuleManager().getBean( "userManager");
		}
	}
	

}
