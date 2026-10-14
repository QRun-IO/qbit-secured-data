/*
 * QQQ - Low-code Application Framework for Engineers.
 * Copyright (C) 2021-2025.  Kingsrook, LLC
 * 651 N Broad St Ste 205 # 6917 | Middletown DE 19709 | United States
 * contact@kingsrook.com
 * https://github.com/Kingsrook/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kingsrook.qbits.secureddata;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;


/*******************************************************************************
 ** Captures every log event, at every level, from every logger while open.
 ** Used by the canary test to prove no protected value reaches a log line.
 *******************************************************************************/
final class LogCapture implements AutoCloseable
{
   private final List<String> lines = new ArrayList<>();
   private final Map<String, Level> originalLevels = new HashMap<>();
   private final LoggerContext context;
   private final Appender appender;



   /*******************************************************************************
    ** Attach to the root logger and force all configured loggers to ALL.
    *******************************************************************************/
   LogCapture()
   {
      context = (LoggerContext) LogManager.getContext(false);
      Configuration configuration = context.getConfiguration();
      appender = new AbstractAppender("secured-data-log-capture", null, null, true, Property.EMPTY_ARRAY)
      {
         @Override
         public void append(LogEvent event)
         {
            StringBuilder line = new StringBuilder(event.getLoggerName()).append(' ').append(event.getMessage().getFormattedMessage());
            for(Throwable t = event.getThrown(); t != null; t = t.getCause())
            {
               line.append(' ').append(t.getClass().getName()).append(' ').append(t.getMessage());
            }
            synchronized(lines)
            {
               lines.add(line.toString());
            }
         }
      };
      appender.start();
      configuration.addAppender(appender);
      List<LoggerConfig> all = new ArrayList<>(configuration.getLoggers().values());
      all.add(configuration.getRootLogger());
      for(LoggerConfig config : all)
      {
         originalLevels.put(config.getName(), config.getLevel());
         config.setLevel(Level.ALL);
      }
      configuration.getRootLogger().addAppender(appender, Level.ALL, null);
      context.updateLoggers();
   }



   /*******************************************************************************
    ** Every captured line so far.
    *******************************************************************************/
   List<String> lines()
   {
      synchronized(lines)
      {
         return (new ArrayList<>(lines));
      }
   }



   /*******************************************************************************
    ** Detach and restore levels.
    *******************************************************************************/
   @Override
   public void close()
   {
      Configuration configuration = context.getConfiguration();
      configuration.getRootLogger().removeAppender(appender.getName());
      for(LoggerConfig config : configuration.getLoggers().values())
      {
         config.setLevel(originalLevels.get(config.getName()));
      }
      configuration.getRootLogger().setLevel(originalLevels.get(configuration.getRootLogger().getName()));
      context.updateLoggers();
      appender.stop();
   }
}
