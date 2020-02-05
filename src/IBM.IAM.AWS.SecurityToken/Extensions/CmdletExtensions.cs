using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Management.Automation;
using System.Text;

    static class CmdletExtensions
    {
        #region ExecuteCmdletInPipeline
        /// <summary>
        /// Execute the given cmdlet in powershell using the given pipeline parameters.
        /// </summary>
        /// <typeparam name="T">The output type for the cmdlet</typeparam>
        /// <param name="cmdlet">The cmdlet to execute</param>
        /// <param name="name">The name of the cmdlet</param>
        /// <param name="cmdletParameters">The parameters to pass to the cmdlet on the pipeline</param>
        /// <param name="ignoreErrors">Do not throw exception if command has errors.</param>
        /// <param name="writeErrors">Write errors to host if command has errors.</param>
        /// <returns>The output of executing the cmdlet</returns>
        /// <exception cref="System.InvalidOperationException">Throws InvalidOperationException if any error occurs from the cmdlet call.</exception>
        public static List<T> ExecuteCmdletInPipeline<T>(this PSCmdlet cmdlet, string name, KeyValuePair<string, object>[] cmdletParameters, bool ignoreErrors = false, bool writeErrors = false)
        {
            List<T> output = new List<T>();
            using (System.Management.Automation.PowerShell powershell = System.Management.Automation.PowerShell.Create(RunspaceMode.CurrentRunspace))
            {
                powershell.AddCommand(name);
                foreach (var pair in cmdletParameters)
                {
                    if (pair.Value == null)
                        powershell.AddParameter(pair.Key);
                    else
                        powershell.AddParameter(pair.Key, pair.Value);
                }
                Collection<PSObject> result = powershell.Invoke();
                if (powershell.Streams.Error != null && powershell.Streams.Error.Count > 0)
                {
                    StringBuilder details = new StringBuilder();
                    if (writeErrors)
                        powershell.Streams.Error.ForEach(e => cmdlet.WriteError(e));
                    powershell.Streams.Error.ForEach(e => details.AppendLine($"Error: {e}"));
                    InvalidOperationException ex;
                    if (powershell.Streams.Error[0].Exception != null)
                        ex = new InvalidOperationException($"Errors while running cmdlet:\n {details}", powershell.Streams.Error[0].Exception);
                    else
                        ex = new InvalidOperationException($"Errors while running cmdlet:\n {details}");
                    int i = 0;
                    powershell.Streams.Error.ForEach(e => ex.Data.Add($"ErrorRecord{i++}", e));
                    if (!ignoreErrors)
                        throw ex;
                }

                if (result != null && result.Count > 0)
                {
                    result.ForEach(r => output.Add((T)r.BaseObject));
                }
            }

            return output;
        }
        /// <exception cref="System.InvalidOperationException">Throws InvalidOperationException if any error occurs from the cmdlet call.</exception>
        public static List<T> ExecuteCmdletInPipeline<T>(this PSCmdlet cmdlet, string name, object cmdletParameters, bool ignoreErrors = false, bool writeErrors = false)
        {
            return cmdlet.ExecuteCmdletInPipeline<T>(name, cmdletParameters.ToKeyValuePair(), ignoreErrors, writeErrors);
        }
        /// <exception cref="System.InvalidOperationException">Throws InvalidOperationException if any error occurs from the cmdlet call.</exception>
        public static List<T> ExecuteCmdletInPipeline<T>(this PSCmdlet cmdlet, string name)
        {
            return cmdlet.ExecuteCmdletInPipeline<T>(name, Array.Empty<KeyValuePair<string, object>>());
        }

        // With object returned
        /// <exception cref="System.InvalidOperationException">Throws InvalidOperationException if any error occurs from the cmdlet call.</exception>
        public static List<object> ExecuteCmdletInPipeline(this PSCmdlet cmdlet, string name, object cmdletParameters)
        {
            return cmdlet.ExecuteCmdletInPipeline<object>(name, cmdletParameters.ToKeyValuePair());
        }
        /// <exception cref="System.InvalidOperationException">Throws InvalidOperationException if any error occurs from the cmdlet call.</exception>
        public static List<object> ExecuteCmdletInPipeline(this PSCmdlet cmdlet, string name)
        {
            return cmdlet.ExecuteCmdletInPipeline<object>(name, Array.Empty<KeyValuePair<string, object>>());
        }
        #endregion


        /// <summary>
        /// Perform an action on each element of a sequence.
        /// </summary>
        /// <typeparam name="T">Type of elements in the sequence.</typeparam>
        /// <param name="sequence">The sequence.</param>
        /// <param name="action">The action to perform.</param>
        public static void ForEach<T>(this IEnumerable<T> sequence, Action<T> action)
        {
            Debug.Assert(sequence != null, "sequence cannot be null!");
            Debug.Assert(action != null, "action cannot be null!");

            foreach (T element in sequence)
            {
                action(element);
            }
        }

        public static KeyValuePair<string, object>[] ToKeyValuePair(this object source, bool ignoreNullValues = true)
        {
            List<KeyValuePair<string, object>> table = new List<KeyValuePair<string, object>>();
            if (source != null)
            {
                var type = source.GetType();
                var props = type.GetProperties();
                Array.ForEach(props, (p) => {
                    var val = p.GetValue(source);
                    if (val == null && ignoreNullValues)
                        return;
                    table.Add(new KeyValuePair<string, object>(p.Name, val));
                });
            }

            return table.ToArray();
        }

    }
